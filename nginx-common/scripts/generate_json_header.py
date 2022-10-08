#!/usr/bin/env python
from utils import writeText
import json
import sys
import re
import os

def cEscapeString(fixed):
    if len(fixed) < 50:
        return json.dumps(fixed)

    res = []
    pos = 0
    while True:
        comma = fixed.find(',', pos + 2)
        if comma < 0:
            res.append(fixed[pos:])
            break
        res.append(fixed[pos:comma])
        pos = comma
    return ' '.join(map(json.dumps, res))

def writeErr(msg):
    sys.stderr.write(msg + '\n')

def addVarDef(varSet, varType, varName):
    # move any *'s from varType to varName
    varName = '*' * varType.count('*') + varName
    varType = varType.replace('*', '')
    varSet.add((varType, varName))

def renderVarDefs(varDefs):
    if len(varDefs) == 0:
        return ''

    varDefs = sorted(varDefs, key=lambda v: (len(v[0]), len(v[1])))
    maxTypeLen = max(map(lambda x: len(x[0]), varDefs))
    maxPtrLevel = max(map(lambda x: x[1].count('*'), varDefs))

    result = ''
    for varType, varName in varDefs:
        spaceCount = maxTypeLen + 2 - len(varType)
        spaceCount += maxPtrLevel - varName.count('*')
        result += '    %s%s%s;\n' % (varType, ' ' * spaceCount, varName)
    result += '\n'
    return result

# json reader

def ngx_hash(s):
    res = 0
    for ch in s:
        res = (res * 31 + ord(ch)) & ((1 << 64) - 1)
    return res

def getHash(stringList):
    hashMap = {ngx_hash(s): s for s in stringList}
    if len(hashMap) != len(stringList):
        writeErr('Error: hash conflict %s' % stringList)
        sys.exit(1)

    size = len(stringList)
    while True:
        cur = {x % size:hashMap[x] for x in hashMap}
        if len(cur) == len(stringList):
            break

        if size >= 20 * len(stringList):
            writeErr('Error: failed to find hash size %s' % stringList)
            sys.exit(1)
        size += 1

    return size, cur

def getObjectReader(objectInfo, properties):
    structDef = []
    propDefs = ''
    for property in properties:
        fieldName, format = property[:2]
        post = 'NULL'
        if format == '%V':
            cTypeName = 'ngx_str_t'
            jsonTypeName = 'NGX_JSON_STRING'
            setterName = 'str'
        elif format == '%rV':
            cTypeName = 'ngx_str_t'
            jsonTypeName = 'NGX_JSON_STRING'
            setterName = 'raw_str'
        elif format == '%b':
            cTypeName = 'ngx_flag_t'
            jsonTypeName = 'NGX_JSON_BOOL'
            setterName = 'flag'
        elif format == '%L':
            cTypeName = 'int64_t'
            jsonTypeName = 'NGX_JSON_INT'
            setterName = 'num'
        elif format == '%a':
            cTypeName = 'ngx_json_array_t*'
            jsonTypeName = 'NGX_JSON_ARRAY'
            setterName = 'arr'
        elif format == '%o':
            cTypeName = 'ngx_json_object_t*'
            jsonTypeName = 'NGX_JSON_OBJECT'
            setterName = 'obj'
        elif format.startswith('%enum-'):
            cTypeName = 'ngx_uint_t'
            jsonTypeName = 'NGX_JSON_STRING'
            setterName = 'enum'
            post = '&%s' % format[len('%enum-'):]
        else:
            writeErr('Error: unknown format %s' % format)
            sys.exit(1)

        structDef.append((cTypeName, fieldName))

        propDefs += '''static ngx_json_prop_t  %s_%s = {
    ngx_string(%s),
    %sULL,
    %s,
    ngx_json_set_%s_slot,
    offsetof(%s_t, %s),
    %s
};\n\n\n''' % (objectInfo[0], fieldName, cEscapeString(fieldName),
             ngx_hash(fieldName), jsonTypeName, setterName, objectInfo[0],
             fieldName, post)


    header = '/* %s reader */\n\n' % objectInfo[0]

    # struct
    maxTypeLen = max(map(lambda x: len(x[0]), structDef))
    struct = 'typedef struct {\n'
    for cTypeName, fieldName in structDef:
        cTypeBaseName = cTypeName.rstrip('*')
        cTypePtrs = cTypeName[len(cTypeBaseName):]
        alignment = ' ' * (maxTypeLen - len(cTypeName))
        struct += '    %s%s  %s%s;\n' % (cTypeBaseName, alignment, cTypePtrs,
                                         fieldName)
    struct += '} %s_t;\n\n\n' % objectInfo[0]

    # hash
    size, hash = getHash([x[1] for x in structDef])
    hashText = 'static ngx_json_prop_t  *%s[] = {\n' % objectInfo[0]
    for index in range(size):
        if index in hash:
            hashText += '    &%s_%s,\n' % (objectInfo[0], hash[index])
        else:
            hashText += '    NULL,\n'
    hashText += '};\n\n\n'

    return header + struct + propDefs + hashText


# json writer

def fixedStringLen(fixed):
    return 'sizeof(%s) - 1' % fixed

def fixedStringCopy(fixed):
    if (fixed[0] == '"' and fixed[-1] == '"' and
        (len(fixed) == 3 or (len(fixed) == 4 and fixed[1] == '\\'))):
        return "*p++ = '%s';\n" % fixed[1:-1]

    return 'p = ngx_copy_fix(p, %s);\n' % (fixed)

def listAdd(lst, item):
    # Note: not using set in order to retain order
    if item not in lst:
        lst.append(item)

def getObjectWriter(objectInfo, properties):
    static = 'static '
    if objectInfo[0] == 'nostatic':
        static = ''
        objectInfo = objectInfo[1:]
    if objectInfo[0] == 'noobject':
        prefix = suffix = ''
        objectInfo = objectInfo[1:]
    elif objectInfo[0].startswith('key('):
        prefix = '"%s":{' % objectInfo[0][4:-1]
        suffix = '}'
        objectInfo = objectInfo[1:]
    else:
        prefix = '{'
        suffix = '}'
    outputBaseFunc = objectInfo[0]

    args = ''
    defaultExprBase = ''
    if len(objectInfo) > 1:
        objectType = objectInfo[1]
        args = '%s *obj' % objectType
        defaultExprBase = 'obj->'
    if len(objectInfo) > 2:
        args += ', %s' % ' '.join(objectInfo[2:])


    sizeCalc = ''
    getSizeCode = ''
    writeCode = ''
    skipCond = ''
    funcDefs = []
    varDefs = set([])
    writeVarDefs = set([])
    writeDefs = []
    returnConds = {}
    forwardConds = {}
    fixed = prefix
    nextFixed = ''
    firstField = True
    for property in properties:
        if property[1] == '%code':
            listAdd(funcDefs, ' '.join(property[2:]))
            continue

        if property[1] == '%writeCode':
            listAdd(writeDefs, ' '.join(property[2:]))
            continue

        if property[1] == '%var':
            addVarDef(varDefs, property[2], property[3])
            continue

        if property[1] == '%writeVar':
            addVarDef(writeVarDefs, property[2], property[3])
            continue

        if property[1] == '%skipCond':
            skipCond = ' '.join(property[2:])
            continue

        if property[1].startswith('%return'):
            if '-' in property[1]:
                value = cEscapeString(property[1].split('-', 1)[1])
            else:
                value = ''
            returnConds[' '.join(property[2:])] = value
            continue

        fieldName, format = property[:2]
        if len(property) > 2:
            expr = ' '.join(property[2:])
        else:
            expr = defaultExprBase

        if expr == '' or expr.endswith('->') or expr.endswith('.'):
            expr += fieldName

        if format.startswith('%forward-'):
            baseFunc = format.split('-', 1)[1]
            forwardConds[expr] = baseFunc
            continue

        if not firstField:
            fixed += ','
        if fieldName != '-':
            fixed += '"%s":' % fieldName
        firstField = False

        if format.startswith('%'):
            format = format[1:]
            if (format.startswith('func-') or format.startswith('objFunc-') or
                format.startswith('arrFunc-')):
                baseFunc = format.split('-', 1)[1]

                if format.startswith('objFunc-'):
                    fixed += '{'
                    nextFixed = '}'
                elif format.startswith('arrFunc-'):
                    fixed += '['
                    nextFixed = ']'

                if len(expr) > 0:
                    expr = ', %s' % expr

                if fixed.endswith(','):
                    addVarDef(writeVarDefs, 'u_char', '*next')
                    valueWrite = 'next = %s_write(p%s);' % (baseFunc, expr)
                    valueWrite += '\n' + 'p = next == p ? p - 1 : next;'
                else:
                    valueWrite = 'p = %s_write(p%s);' % (baseFunc, expr)

                valueSize = '%s_get_size(%s)' % (baseFunc, expr[2:])
            elif format.startswith('objQueue-'):
                params = format[len('objQueue-'):].split(',')
                baseFunc, objectType, queueNode, idField, escField = params
                fixed += '{'
                nextFixed = '}'

                getSizeCode += '''
for (q = ngx_queue_head(&%s);
    q != ngx_queue_sentinel(&%s);
    q = ngx_queue_next(q))
{
    cur = ngx_queue_data(q, %s, %s);
    result += cur->%s.len + cur->%s;
    result += %s_get_size(cur) + sizeof(",\\"\\":") - 1;
}
''' % (expr, expr, objectType, queueNode, idField, escField,
        baseFunc)

                valueWrite = '''
for (q = ngx_queue_head(&%s);
    q != ngx_queue_sentinel(&%s);
    q = ngx_queue_next(q))
{
    cur = ngx_queue_data(q, %s, %s);

    if (p[-1] != '{') {
        *p++ = ',';
    }

    *p++ = '"';
    p = ngx_json_str_write_escape(p, &cur->%s, cur->%s);
    *p++ = '"';
    *p++ = ':';
    p = %s_write(p, cur);
}
''' % (expr, expr, objectType, queueNode, idField, escField, baseFunc)

                addVarDef(varDefs, 'ngx_queue_t', '*q')
                addVarDef(varDefs, objectType, '*cur')
                valueSize = ''
            elif format.startswith('objQueueIds-'):
                params = format[len('objQueueIds-'):].split(',')
                objectType, queueNode, idField, escField = params
                fixed += '['
                nextFixed = ']'

                getSizeCode += '''
for (q = ngx_queue_head(&%s);
    q != ngx_queue_sentinel(&%s);
    q = ngx_queue_next(q))
{
    cur = ngx_queue_data(q, %s, %s);
    result += cur->%s.len + cur->%s + sizeof(",\\"\\"") - 1;
}
''' % (expr, expr, objectType, queueNode, idField, escField)

                valueWrite = '''
for (q = ngx_queue_head(&%s);
    q != ngx_queue_sentinel(&%s);
    q = ngx_queue_next(q))
{
    cur = ngx_queue_data(q, %s, %s);

    if (p[-1] != '[') {
        *p++ = ',';
    }

    *p++ = '"';
    p = ngx_json_str_write_escape(p, &cur->%s, cur->%s);
    *p++ = '"';
}
''' % (expr, expr, objectType, queueNode, idField, escField)

                addVarDef(varDefs, 'ngx_queue_t', '*q')
                addVarDef(varDefs, objectType, '*cur')
                valueSize = ''
            elif format.startswith('slist-'):
                params = format[len('slist-'):].split(',')
                baseFunc, objectType = params
                fixed += '['
                nextFixed = ']'

                getSizeCode += '''
for (cur = %s; cur; cur = cur->next) {
    result += %s_get_size(cur) + sizeof(",") - 1;
}
''' % (expr, baseFunc)

                valueWrite = '''
for (cur = %s; cur; cur = cur->next) {

    if (p[-1] != '[') {
        *p++ = ',';
    }

    p = %s_write(p, cur);
}
''' % (expr, baseFunc)

                addVarDef(varDefs, objectType, '*cur')
                valueSize = ''
            elif format.startswith('queue-'):
                params = format[len('queue-'):].split(',')
                baseFunc, objectType, queueNode = params
                fixed += '['
                nextFixed = ']'

                getSizeCode += '''
for (q = ngx_queue_head(&%s);
    q != ngx_queue_sentinel(&%s);
    q = ngx_queue_next(q))
{
    cur = ngx_queue_data(q, %s, %s);
    result += %s_get_size(cur) + sizeof(",") - 1;
}
''' % (expr, expr, objectType, queueNode, baseFunc)

                valueWrite = '''
for (q = ngx_queue_head(&%s);
    q != ngx_queue_sentinel(&%s);
    q = ngx_queue_next(q))
{
    cur = ngx_queue_data(q, %s, %s);

    if (p[-1] != '[') {
        *p++ = ',';
    }

    p = %s_write(p, cur);
}
''' % (expr, expr, objectType, queueNode, baseFunc)

                addVarDef(varDefs, 'ngx_queue_t', '*q')
                addVarDef(varDefs, objectType, '*cur')
                valueSize = ''
            elif format.startswith('array-'):
                params = format[len('array-'):].split(',')
                baseFunc, objectType = params
                fixed += '['
                nextFixed = ']'
                objectTypePtr = '*' * (objectType.count('*') + 1)
                objectTypePtr = objectType.rstrip('*') + ' ' + objectTypePtr
                if skipCond != '':
                    skipCond = '''
    if (%s) {
        continue;
    }
''' % skipCond

                getSizeCode += '''
for (n = 0; n < %s.nelts; n++) {
    cur = ((%s) %s.elts)[n];
%s
    result += %s_get_size(cur) + sizeof(",") - 1;
}
''' % (expr, objectTypePtr, expr, skipCond, baseFunc)
                valueWrite = '''
for (n = 0; n < %s.nelts; n++) {
    cur = ((%s) %s.elts)[n];
%s
    if (p[-1] != '[') {
        *p++ = ',';
    }

    p = %s_write(p, cur);
}
''' % (expr, objectTypePtr, expr, skipCond, baseFunc)
                addVarDef(varDefs, 'ngx_uint_t', 'n')
                addVarDef(varDefs, objectType, 'cur')
                valueSize = ''
                skipCond = ''
            elif format == 'jV':
                fixed += '"'
                nextFixed = '"'
                valueWrite = 'p = ngx_json_str_write(p, &%s);' % expr
                valueSize = 'ngx_json_str_get_size(&%s)' % expr
            elif format == 'rV':
                fixed += '"'
                nextFixed = '"'
                valueWrite = 'p = ngx_copy_str(p, %s);' % expr
                valueSize = '%s.len' % expr
            elif format == 'V':
                fixed += '"'
                nextFixed = '"'
                valueWrite = (
                    'p = (u_char *) ngx_escape_json(p, %s.data, %s.len);' %
                    (expr, expr))
                valueSize =  (
                    '%s.len + ngx_escape_json(NULL, %s.data, %s.len)' %
                    (expr, expr, expr))
            elif format == 'bs':
                fixed += '"'
                nextFixed = '"'
                valueWrite = 'p = ngx_block_str_copy(p, &%s);' % expr
                valueSize = '%s.len' % expr
            elif format == 'xV':
                fixed += '"'
                nextFixed = '"'
                valueWrite = ('p = ngx_hex_dump(p, %s.data, %s.len);' %
                    (expr, expr))
                valueSize = '%s.len * 2' % expr
            elif format == '4cc':
                fixed += '"'
                nextFixed = '"'
                valueWrite = ('p = (u_char *) ngx_escape_json(p, ' +
                    '(u_char *) &%s, sizeof(uint32_t));' % expr)
                valueSize = ('sizeof(uint32_t) + ngx_escape_json(NULL, ' +
                    '(u_char *) &%s, sizeof(uint32_t))' % expr)
            elif format == 'b':
                if expr in ['true', 'false']:
                    fixed += expr
                    continue

                valueSize = 'sizeof("false") - 1'
                valueWrite = '''if (%s) {
    p = ngx_copy_fix(p, "true");

} else {
    p = ngx_copy_fix(p, "false");
}
''' % expr
            elif format.startswith('enum-'):
                fixed += '"'
                nextFixed = '"'
                valuesName = format[len('enum-'):]
                valueStr = '%s[%s]' % (valuesName, expr)
                # Note: assuming that enum values do not require escaping
                valueSize = '%s.len' % valueStr
                valueWrite = 'p = ngx_sprintf(p, "%%V", &%s);' % valueStr
            elif format.startswith('.') and format.endswith('F'):
                precision = int(format[1:-1])
                valueSize = 'NGX_INT32_LEN + %s' % (1 + precision)
                format = '%uD.%0' + str(precision) + 'uD'
                printParams = '(uint32_t) (n / d)'
                printParams += (', (uint32_t) (n %% d * %d) / d''' %
                    (10 ** precision))
                addVarDef(writeVarDefs, 'uint32_t', 'n, d')
                valueWrite = '''d = %s.denom;
if (d) {
    n = %s.num;
    p = ngx_sprintf(p, "%s", %s);

} else {
    *p++ = '0';
}
''' % (expr, expr, format, printParams)
            else:
                scale = None
                match = re.match('^\.(\d+)(\w+)$', format)
                if match is not None:
                    precision = int(match.groups()[0])
                    format = match.groups()[1]
                    if format == 'f':
                        valueSize = ('NGX_INT64_LEN + %s' % (precision + 1))
                        cast = 'double'
                    elif format == 'uD':
                        valueSize = 'NGX_INT32_LEN + 1'
                        cast = 'uint32_t'
                        scale = 10 ** precision
                        format += '.%%0%suD' % precision
                    else:
                        writeErr('Error: unknown format %s' % format)
                        sys.exit(1)
                elif format == 'L':
                    valueSize = 'NGX_INT64_LEN'
                    cast = 'int64_t'
                elif format == 'uL':
                    valueSize = 'NGX_INT64_LEN'
                    cast = 'uint64_t'
                elif format == '016uxL':
                    fixed += '"'
                    nextFixed = '"'
                    valueSize = '16'
                    cast = 'uint64_t'
                elif format == 'uD':
                    valueSize = 'NGX_INT32_LEN'
                    cast = 'uint32_t'
                elif format == 'i':
                    valueSize = 'NGX_INT_T_LEN'
                    cast = 'ngx_int_t'
                elif format == 'ui':
                    valueSize = 'NGX_INT_T_LEN'
                    cast = 'ngx_uint_t'
                elif format == 'T':
                    valueSize = 'NGX_TIME_T_LEN'
                    cast = 'time_t'
                elif format == 'uA':
                    valueSize = 'NGX_INT_T_LEN'
                    cast = 'ngx_atomic_uint_t'
                elif format == 'uz':
                    valueSize = 'NGX_SIZE_T_LEN'
                    cast = 'size_t'
                elif format == 'O':
                    valueSize = 'NGX_OFF_T_LEN'
                    cast = 'off_t'
                elif format == 'M':
                    valueSize = 'NGX_INT64_LEN'
                    cast = 'ngx_msec_t'
                else:
                    writeErr('Error: unknown format %s' % format)
                    sys.exit(1)

                if scale is not None:
                    valueWrite = (('p = ngx_sprintf(p, "%s", ' +
                        '(%s) (%s / %s), (uint32_t) (%s %% %s));') %
                        ('%' + format, cast, expr, scale, expr, scale))
                else:
                    valueWrite = ('p = ngx_sprintf(p, "%s", (%s) %s);' %
                        ('%' + format, cast, expr))

        else:
            fixed += '"%s"' % format
            continue

        if len(fixed) > 0:
            fixed = cEscapeString(fixed)
            writeCode += fixedStringCopy(fixed)
            sizeCalc += fixedStringLen(fixed) + ' + '

        writeCode += '%s\n' % valueWrite
        if len(valueSize) > 0:
            valueSize += ' +'
        sizeCalc += '%s\n' % valueSize

        fixed = nextFixed
        nextFixed = ''

    fixed += suffix

    if len(fixed) > 0:
        fixed = cEscapeString(fixed)
        writeCode += fixedStringCopy(fixed)
        sizeCalc += fixedStringLen(fixed)
    elif sizeCalc.endswith(' +\n'):
        sizeCalc = sizeCalc[:-3]

    funcDefs = ''.join(map(lambda x: '    %s\n' % x, funcDefs))
    writeDefs = ''.join(map(lambda x: '    %s\n' % x, writeDefs))

    checks = ''
    for cond, value in returnConds.items():
        if value != '':
            size = fixedStringLen(value)
        else:
            size = 0
        checks += '''    if (%s) {
        return %s;
    }

''' % (cond, size)

    for cond, baseFunc in forwardConds.items():
        checks += '''    if (%s) {
        return %s_get_size(obj);
    }

''' % (cond, baseFunc)

    varDefsStr = renderVarDefs(varDefs.union(set([('size_t', 'result')])))
    sizeArgs = args if len(args) > 0 else 'void'

    result = '/* %s writer */\n\n' % outputBaseFunc

    result += '''%ssize_t
%s_get_size(%s)
{
%s    result =
        %s;
%s
    return result;
}

''' % (static, outputBaseFunc, sizeArgs, varDefsStr + funcDefs + checks,
    sizeCalc.replace('\n', '\n        '), getSizeCode.replace('\n', '\n    '))

    checks = ''
    for cond, value in returnConds.items():
        if value != '':
            write = '        ' + fixedStringCopy(value)
        else:
            write = ''
        checks += '''    if (%s) {
%s        return p;
    }

''' % (cond, write)

    for cond, baseFunc in forwardConds.items():
        checks += '''    if (%s) {
        return %s_write(p, obj);
    }

''' % (cond, baseFunc)

    if len(args) > 0:
        args = ', %s' % args

    varDefsStr = renderVarDefs(varDefs.union(writeVarDefs))

    result += '''\n%su_char *
%s_write(u_char *p%s)
{
%s    %s
    return p;
}


''' % (static, outputBaseFunc, args, varDefsStr + funcDefs + writeDefs + checks,
    writeCode.replace('\n', '\n    '))

    return result


# main

if len(sys.argv) < 2:
    print('Usage:\n\t%s <objects definition file>' %
        os.path.basename(__file__))
    sys.exit(1)

inputFile = sys.argv[1]

objects = []
properties = []
for curLine in open(inputFile):
    strippedLine = curLine.strip()
    if len(strippedLine) == 0:
        continue

    splittedLine = strippedLine.split()
    if not curLine.startswith('\t') and not curLine.startswith(' '):
        if len(properties) > 0:
            objects.append((objectInfo, properties))
        objectInfo = splittedLine
        properties = []
        continue

    properties.append(splittedLine)

if len(properties) > 0:
    objects.append((objectInfo, properties))


result = '/* auto-generated by %s */\n\n' % os.path.basename(__file__)

if 'in' in map(lambda x: x[0][0], objects):
    result += '''#ifndef ngx_array_entries
#define ngx_array_entries(x)     (sizeof(x) / sizeof(x[0]))
#endif

'''

if 'out' in map(lambda x: x[0][0], objects):
    result += '''#ifndef ngx_copy_fix
#define ngx_copy_fix(dst, src)   ngx_copy(dst, (src), sizeof(src) - 1)
#endif

#ifndef ngx_copy_str
#define ngx_copy_str(dst, src)   ngx_copy(dst, (src).data, (src).len)
#endif

'''

for objectInfo, properties in objects:
    if objectInfo[0] == 'in':
        result += getObjectReader(objectInfo[1:], properties)
    elif objectInfo[0] == 'out':
        result += getObjectWriter(objectInfo[1:], properties)
    else:
        writeErr('Error: invalid object type %s, must be in/out' %
            objectInfo[0])
        sys.exit(1)

writeText(result.strip())
