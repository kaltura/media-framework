import os

def get_config_deps(file_path):
    config_deps = set([])
    with open(file_path, 'rt') as f:
        for cur_line in f:
            cur_line = cur_line.strip()
            if 'ngx_addon_dir' not in cur_line or '.h' not in cur_line:
                continue

            cur_line = cur_line.rstrip('\\').rstrip()
            cur_line = cur_line.split('/')[-1]
            config_deps.add(cur_line)

    return config_deps

header_files = {}
config_deps = set([])

base_dir = os.path.join(os.path.dirname(__file__), '../..')
base_dir = os.path.normpath(base_dir)

for root, _, files in os.walk(base_dir):
    for name in files:
        file_path = os.path.join(root, name)

        norm_path = file_path.lower().replace('\\', '/')
        if '/transcoder/' in norm_path or '/unused/' in norm_path or '/old/' in norm_path:
            continue

        if name == 'config':
            config_deps.update(get_config_deps(file_path))
        elif os.path.splitext(name)[1] == '.h':
            header_files[name] = file_path

missing_files = config_deps - set(header_files.keys())
for file in missing_files:
    print('Error: missing file referenced in config: %s' % file)

missing_deps = set(header_files.keys()) - config_deps
for file in missing_deps:
    print('Error: header file missing from config deps: %s' % header_files[file])
