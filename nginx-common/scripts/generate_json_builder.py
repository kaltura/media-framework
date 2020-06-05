from utils import writeText
import json
import sys
import re
import os

def cEscapeString(fixed):
    return json.dumps(fixed)

def fixedStringLen(fixed):
    return 'sizeof(%s) - 1' % fixed

def fixedStringCopy(fixed):
    if fixed[0] == '"' and fixed[-1] == '"' and \
        (len(fixed) == 3 or (len(fixed) == 4 and fixed[1] == '\\')):
        return "*p++ = '%s';\n" % fixed[1:-1]

    return 'p = ngx_copy_fix(p, %s);\n' % (fixed)

def outputObject(objectInfo, properties):
    # parse the object info
    static = ''
    if objectInfo[0] == 'static':
        static = 'static '
        objectInfo = objectInfo[1:]
    if objectInfo[0] == 'noobject':
        prefix = suffix = ''
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
    funcDefs = set([])
    writeDefs = set([])
    returnConds = {}
    fixed = prefix
    nextFixed = ''
    firstField = True
    for property in properties:
        if property[1] == '%code':
            funcDefs.add(' '.join(property[2:]))
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

        if not firstField:
            fixed += ','
        if fieldName != '-':
            fixed += '"%s":' % fieldName
        firstField = False

        if format.startswith('%'):
            format = format[1:]
            if format.startswith('func-') or format.startswith('objFunc-') or \
                format.startswith('arrFunc-'):
                baseFunc = format.split('-', 1)[1]

                if format.startswith('objFunc-'):
                    fixed += '{';
                    nextFixed = '}'
                elif format.startswith('arrFunc-'):
                    fixed += '[';
                    nextFixed = ']'

                if len(expr) > 0:
                    expr = ', %s' % expr

                if fixed.endswith(','):
                    writeDefs.add('u_char  *next;');
                    valueWrite = 'next = %s_write(p%s);' % (baseFunc, expr)
                    valueWrite += '\n' + 'p = next == p ? p - 1 : next;'
                else:
                    valueWrite = 'p = %s_write(p%s);' % (baseFunc, expr)

                valueSize = '%s_get_size(%s)' % (baseFunc, expr[2:])
            elif format.startswith('objQueue-'):
                params = format[len('objQueue-'):].split(',')
                baseFunc, objectType, queueNode, idField = params
                fixed += '{';
                nextFixed = '}'

                getSizeCode += '''
for (q = ngx_queue_head(&%s);
    q != ngx_queue_sentinel(&%s);
    q = ngx_queue_next(q))
{
    %s *cur = ngx_queue_data(q, %s, %s);
    result += cur->%s.len + ngx_escape_json(NULL, cur->%s.data, cur->%s.len);
    result += %s_get_size(cur) + sizeof(",\\"\\":") - 1;
}
''' % (expr, expr, objectType, objectType, queueNode, idField, idField,
        idField, baseFunc)

                valueWrite = '''
for (q = ngx_queue_head(&%s);
    q != ngx_queue_sentinel(&%s);
    q = ngx_queue_next(q))
{
    %s *cur = ngx_queue_data(q, %s, %s);

    if (q != ngx_queue_head(&%s))
    {
        *p++ = ',';
    }
    *p++ = '"';
    p = (u_char *) ngx_escape_json(p, cur->%s.data, cur->%s.len);
    *p++ = '"';
    *p++ = ':';
    p = %s_write(p, cur);
}
''' % (expr, expr, objectType, objectType, queueNode, expr, idField,
        idField, baseFunc)

                funcDefs.add('ngx_queue_t  *q;')
                valueSize = ''
            elif format.startswith('slist-'):
                params = format[len('slist-'):].split(',')
                baseFunc, objectType = params
                fixed += '[';
                nextFixed = ']'

                getSizeCode += '''
for (cur = %s; cur; cur = cur->next) {
    result += %s_get_size(cur) + sizeof(",") - 1;
}
''' % (expr, baseFunc)

                valueWrite = '''
for (cur = %s; cur; cur = cur->next) {

    if (cur != %s) {
        *p++ = ',';
    }
    p = %s_write(p, cur);
}
''' % (expr, expr, baseFunc)

                funcDefs.add('%s  *cur;' % objectType)
                valueSize = ''
            elif format.startswith('queue-'):
                params = format[len('queue-'):].split(',')
                baseFunc, objectType, queueNode = params
                fixed += '[';
                nextFixed = ']'

                getSizeCode += '''
for (q = ngx_queue_head(&%s);
    q != ngx_queue_sentinel(&%s);
    q = ngx_queue_next(q))
{
    %s *cur = ngx_queue_data(q, %s, %s);
    result += %s_get_size(cur) + sizeof(",") - 1;
}
''' % (expr, expr, objectType, objectType, queueNode, baseFunc)

                valueWrite = '''
for (q = ngx_queue_head(&%s);
    q != ngx_queue_sentinel(&%s);
    q = ngx_queue_next(q))
{
    %s *cur = ngx_queue_data(q, %s, %s);

    if (q != ngx_queue_head(&%s)) {
        *p++ = ',';
    }
    p = %s_write(p, cur);
}
''' % (expr, expr, objectType, objectType, queueNode, expr, baseFunc)

                funcDefs.add('ngx_queue_t  *q;')
                valueSize = ''
            elif format.startswith('array-'):
                params = format[len('array-'):].split(',')
                baseFunc, objectType = params
                fixed += '[';
                nextFixed = ']'
                getSizeCode += '''
for (n = 0; n < %s.nelts; ++n) {
    %s cur = ((%s*)%s.elts)[n];
    result += %s_get_size(cur) + sizeof(",") - 1;
}
''' % (expr, objectType, objectType, expr, baseFunc)
                valueWrite = '''
for (n = 0; n < %s.nelts; ++n) {
    %s cur = ((%s*)%s.elts)[n];

    if (n > 0) {
        *p++ = ',';
    }
    p = %s_write(p, cur);
}
''' % (expr, objectType, objectType, expr, baseFunc)
                funcDefs.add('ngx_uint_t  n;')
                valueSize = ''
            elif format == 'V':
                fixed += '"';
                nextFixed = '"'
                valueWrite =                                                  \
                    'p = (u_char *) ngx_escape_json(p, %s.data, %s.len);' %   \
                    (expr, expr)
                valueSize =                                                   \
                    '%s.len + ngx_escape_json(NULL, %s.data, %s.len)' %       \
                    (expr, expr, expr)
            elif format == 'bs':
                fixed += '"';
                nextFixed = '"'
                valueWrite = 'p = ngx_block_str_copy(p, &%s);' % expr
                valueSize = '%s.len' % expr
            elif format == 'xV':
                fixed += '"';
                nextFixed = '"'
                valueWrite = 'p = ngx_hex_dump(p, %s.data, %s.len);' %        \
                    (expr, expr)
                valueSize = '%s.len * 2' % expr
            elif format == '4cc':
                fixed += '"';
                nextFixed = '"'
                valueWrite = 'p = (u_char *) ngx_escape_json(p, ' +           \
                    '(u_char *) &%s, sizeof(uint32_t));' % expr
                valueSize = 'sizeof(uint32_t) + ngx_escape_json(NULL, ' +     \
                    '(u_char *) &%s, sizeof(uint32_t))' % expr
            elif format == 'b':
                valueSize = 'sizeof("false") - 1'
                valueWrite = '''if (%s) {
    p = ngx_copy_fix(p, "true");
} else {
    p = ngx_copy_fix(p, "false");
}''' % expr
            elif format.startswith('enum-'):
                fixed += '"';
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
                printParams += ', (uint32_t) (n %% d * %d) / d''' %           \
                    (10 ** precision)
                writeDefs.add('uint32_t  n, d;')
                valueWrite = '''n = %s.num;
d = %s.denom;
p = ngx_sprintf(p, "%s", %s);''' % (expr, expr, format, printParams)
            else:
                match = re.match('^\.(\d+)f$', format)
                if not match is None:
                    valueSize = 'NGX_INT64_LEN + %s' %                        \
                        (int(match.groups()[0]) + 1)
                    cast = 'double'
                elif format == 'L':
                    valueSize = 'NGX_INT64_LEN'
                    cast = 'int64_t'
                elif format == 'uL':
                    valueSize = 'NGX_INT64_LEN'
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
                else:
                    print 'Unknown format %s' % format
                    sys.exit(1)
                valueWrite = 'p = ngx_sprintf(p, "%s", (%s) %s);' %            \
                    ('%' + format, cast, expr)

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

    result = '''
%ssize_t
%s_get_size(%s)
{
%s    size_t  result =
        %s;
%s
    return result;
}

''' % (static, outputBaseFunc, args, funcDefs + checks,
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

    if len(args) > 0:
        args = ', %s' % args

    result += '''%su_char *
%s_write(u_char *p%s)
{
%s    %s
    return p;
}''' % (static, outputBaseFunc, args, funcDefs + writeDefs + checks,
    writeCode.replace('\n', '\n    '))

    writeText(result)

if len(sys.argv) < 2:
    print 'Usage:\n\t%s <objects definition file>' % os.path.basename(__file__)
    sys.exit(1)

inputFile = sys.argv[1]

print '''/* auto-generated by %s */

#ifndef ngx_copy_fix
#define ngx_copy_fix(dst, src)   ngx_copy(dst, (src), sizeof(src) - 1)
#endif
''' % os.path.basename(__file__)

properties = []
for curLine in file(inputFile):
    strippedLine = curLine.strip()
    if len(strippedLine) == 0:
        continue

    splittedLine = strippedLine.split()
    if not curLine.startswith('\t') and not curLine.startswith(' '):
        if len(properties) > 0:
            outputObject(objectInfo, properties)
        objectInfo = splittedLine
        properties = []
        continue

    properties.append(splittedLine)

if len(properties) > 0:
    outputObject(objectInfo, properties)
