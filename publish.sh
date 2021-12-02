#!/bin/bash

docker login
docker build -t scan-report .
docker tag scan-report mawinkler/scan-report:latest
docker push mawinkler/scan-report:latest