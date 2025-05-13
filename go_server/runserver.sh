#!/bin/bash

docker image load --input xserver.tar
docker compose --file docker-compose_prod.yaml up