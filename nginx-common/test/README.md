# Static Analysis Scripts

- *find_unimported_syms.py* - scans the object files generated during compilation, and generates a list of symbols that are exported from an object file, but not imported by any other object file.
    Such symbols may be missing the `static` keyword.
- *openresty-devel-utils* - a slightly modified version of [ngx-releng](https://github.com/openresty/openresty-devel-utils/blob/master/ngx-releng), validates nginx coding conventions.
- *validate_api_doc.py* - compares the list of API routes defined in the source, to the ones documented in the readme file.
- *validate_config_files.py* - checks the config files of the nginx modules, looking for missing dependencies / references to files that do not exist.
- *validate_directives_doc.py* - compares the set of nginx configuration directives defined in the source, to the ones documented in the readme file.
- *validate_json_write.py* - validates JSON write code, by ensuring that a matching `sizeof` exists for all strings written using `ngx_copy_fix`.
- *validate_logs.py* - validates log prints -
    - the number of arguments in the string, matches the number of arguments passed to the log function
    - the function name prefix in the string, matches the name of the function
