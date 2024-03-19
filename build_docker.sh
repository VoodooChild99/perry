#!/bin/bash
DIR=$(dirname "$(realpath "${BASH_SOURCE[0]}")")
IMAGE=perry
CONTAINER_NAME=perry

if [[ -n $(docker ps -a --filter name=$CONTAINER_NAME --format "{{.Names}}") ]]; then
    docker stop $CONTAINER_NAME
    docker rm $CONTAINER_NAME
fi

if [[ -z $1 ]]; then
    TAG=latest
else
    TAG=$1
fi

echo "[*] Building image $IMAGE:$TAG"
docker build -t $IMAGE:"$TAG" "$DIR" \
    --build-arg "HTTP_PROXY=$PROXY_ADDRESS" \
    --build-arg "HTTPS_PROXY=$PROXY_ADDRESS" \
    --build-arg "http_proxy=$PROXY_ADDRESS" \
    --build-arg "https_proxy=$PROXY_ADDRESS"