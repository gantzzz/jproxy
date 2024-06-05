#!/bin/bash

docker login ghcr.io/gantzzz && \
docker build -t ghcr.io/gantzzz/jproxy:latest . && \
docker push ghcr.io/gantzzz/jproxy:latest
