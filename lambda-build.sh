#!/bin/bash -ex
docker build --tag s3-meter-lambda:latest --rm .
mkdir -p export
docker run --volume ${PWD}/export:/export s3-meter-lambda:latest \
  cp /lambda.zip /export/lambda.zip
