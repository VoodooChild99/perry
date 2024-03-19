#!/bin/bash
CONTAINER_NAME=perry

if [[ -n $(docker ps -a --filter name=$CONTAINER_NAME --format "{{.Names}}") ]]; then
    docker stop $CONTAINER_NAME
    docker rm $CONTAINER_NAME
fi