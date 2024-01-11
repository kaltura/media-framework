OPENRESTY_VERSION="1.17.8.2"
OPENRESTY_DOCKER_VERSION="1.25.3.1-0"
echo "building  kaltura/live-front-src"
docker build -t kaltura/live-front-src:latest -f nginx-pckg-module/Dockerfile-live-front-src .
if [ $? -ne 0 ]
then
  echo "failed to build kaltura/live-front-src" >&2
  exit 1
fi
echo "Successfully built kaltura/live-front-src"
if ! [ -d 'docker-openresty' ]; then git clone --branch $OPENRESTY_DOCKER_VERSION https://github.com/openresty/docker-openresty.git; fi
cd docker-openresty
docker build -t kaltura/live-front:$tag -t kaltura/live-front:latest \
--build-arg RESTY_VERSION="$OPENRESTY_VERSION" \
--build-arg RESTY_IMAGE_BASE="kaltura/live-front-src" \
--build-arg RESTY_IMAGE_TAG="latest" \
--build-arg RESTY_EVAL_POST_MAKE="rm -rf /tmp/nginx-secure-token-module /tmp/nginx_mod_akamai_g2o /tmp/nginx-common /tmp/nginx-pckg-module" \
--build-arg RESTY_CONFIG_OPTIONS_MORE="--add-dynamic-module=/tmp/nginx-secure-token-module --add-dynamic-module=/tmp/nginx_mod_akamai_g2o --add-dynamic-module=/tmp/nginx-common --add-dynamic-module=/tmp/nginx-pckg-module" \
. -f alpine/Dockerfile
if [ $? -ne 0 ]
then
  echo "failed to build kaltura/live-front" >&2
  exit 1
fi
echo "Successfully built kaltura/live-front"