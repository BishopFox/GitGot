#!/bin/bash

if [ -z $(docker images -q gitgot) ]; then
    docker build -t gitgot .
fi

docker run -e GITHUB_ACCESS_TOKEN=$GITHUB_ACCESS_TOKEN --mount type=bind,source="$(pwd)",target=/gitgot -it gitgot $@
