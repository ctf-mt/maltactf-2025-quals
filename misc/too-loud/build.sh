#!/bin/bash

REPOSITORY_URL="europe-west1-docker.pkg.dev/friendly-maltese-citizens/misc"
IMAGE_NAME="too-loud"

cd challenge && docker build -t "${REPOSITORY_URL}/${IMAGE_NAME}" . \
	&& docker push "${REPOSITORY_URL}/${IMAGE_NAME}"