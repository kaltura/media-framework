NGINX_ROOT=/usr/local/src/nginx
gcc main.c ../../src/ngx_json_pretty.c -o json_pretty -I../../src/ -I$NGINX_ROOT/src/core/ -I$NGINX_ROOT/objs/ -I$NGINX_ROOT/src/os/unix/
