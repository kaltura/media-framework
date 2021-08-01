import commands
import sys
import os

def get_imports(obj_file):
    return commands.getoutput(
        "readelf -Ws %s | grep -w UND | grep -w GLOBAL | awk '{print $NF}'" %
        obj_file).split('\n')

def get_exports(obj_file):
    return commands.getoutput(
        "readelf -Ws %s | grep -vw UND | grep -w GLOBAL | awk '{print $NF}'" %
        obj_file).split('\n')

if len(sys.argv) < 2:
    print('Usage:\n\t%s <objs-path>' %
        os.path.basename(sys.argv[0]))
    sys.exit(1)

objs_path = sys.argv[1]

imports = set([])
exports = set([])
for root, dirs, files in os.walk(objs_path):
    for name in files:
        file_ext = os.path.splitext(name)[1]
        if file_ext != '.o':
            continue
        cur_path = os.path.join(root, name)
        imports.update(get_imports(cur_path))
        exports.update(get_exports(cur_path))

unused = list(exports - imports)
for sym in sorted(unused):
    print sym
