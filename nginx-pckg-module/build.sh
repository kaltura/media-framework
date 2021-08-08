OPENRESTY_VERSION="1.17.8.2"
echo "building  kaltura/front-live-src"
docker build -t kaltura/front-live-src:latest -f nginx-pckg-module/Dockerfile-front-live-src .
if [ $? -ne 0 ]
then
  echo "failed to build kaltura/front-live-src" >&2
  exit 1
fi
echo "Successfully built kaltura/front-live-src"
if ! [ -d 'docker-openresty' ]; then git clone https://github.com/openresty/docker-openresty.git; fi
cd docker-openresty
docker build -t kaltura/front-live:$tag -t kaltura/front-live:latest \
--build-arg RESTY_VERSION="$OPENRESTY_VERSION" \
--build-arg RESTY_IMAGE_BASE="kaltura/front-live-src" \
--build-arg RESTY_IMAGE_TAG="latest" \
--build-arg RESTY_EVAL_POST_MAKE="rm -rf /tmp/nginx-secure-token-module /tmp/nginx_mod_akamai_g2o /tmp/nginx-common /tmp/nginx-pckg-module" \
--build-arg RESTY_CONFIG_OPTIONS_MORE="--add-dynamic-module=/tmp/nginx-secure-token-module --add-dynamic-module=/tmp/nginx_mod_akamai_g2o --add-dynamic-module=/tmp/nginx-common --add-dynamic-module=/tmp/nginx-pckg-module" \
. -f alpine/Dockerfile
if [ $? -ne 0 ]
then
  echo "failed to build kaltura/front-live" >&2
  exit 1
fi
echo "Successfully built kaltura/front-live"