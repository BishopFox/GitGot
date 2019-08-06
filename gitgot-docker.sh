#!/bin/bash

if [[ -f "Dockerfile" && -f "gitgot.py" ]]; then
    if [ -z $(docker images -q gitgot) ]; then
        # Display output on fresh container build
        docker build -t gitgot .
    else
        # Silent rebuild if in project directory
        docker build -t gitgot . 2>&1 > /dev/null
    fi
else
    echo "Not in project directory. Skipping container update/rebuild..."
fi

if [[ ! -d "logs" || ! -d "states" ]]; then
    mkdir logs states
fi

docker run --rm -it \
    -e GITHUB_ACCESS_TOKEN=$GITHUB_ACCESS_TOKEN \
    -v $PWD/logs:/gitgot/logs \
    -v $PWD/states:/gitgot/states \
    gitgot "$@"
