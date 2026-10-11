#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

docker build -t astro-xss-6.3.1:fixture \
  --build-arg ASTRO_VERSION=6.3.1 --build-arg NODE_ADAPTER_VERSION=10.0.6 --build-arg REACT_ADAPTER_VERSION=6.0.6 xss-app
docker build -t astro-xss-6.1.5:fixture \
  --build-arg ASTRO_VERSION=6.1.5 --build-arg NODE_ADAPTER_VERSION=10.0.6 --build-arg REACT_ADAPTER_VERSION=6.0.6 xss-app
docker build -t astro-xss-6.1.6:fixture \
  --build-arg ASTRO_VERSION=6.1.6 --build-arg NODE_ADAPTER_VERSION=10.0.6 --build-arg REACT_ADAPTER_VERSION=6.0.6 xss-app
docker build -t astro-xss-6.3.3:fixture \
  --build-arg ASTRO_VERSION=6.3.3 --build-arg NODE_ADAPTER_VERSION=10.0.6 --build-arg REACT_ADAPTER_VERSION=6.0.6 xss-app
docker build -t astro-xss-6.1.5:fixture \
  --build-arg ASTRO_VERSION=6.1.5 --build-arg NODE_ADAPTER_VERSION=10.0.6 --build-arg REACT_ADAPTER_VERSION=6.0.6 xss-app
docker build -t astro-xss-6.1.6:fixture \
  --build-arg ASTRO_VERSION=6.1.6 --build-arg NODE_ADAPTER_VERSION=10.0.6 --build-arg REACT_ADAPTER_VERSION=6.0.6 xss-app
docker build -t astro-xss-7.0.9:fixture \
  --build-arg ASTRO_VERSION=7.0.9 --build-arg NODE_ADAPTER_VERSION=11.0.2 --build-arg REACT_ADAPTER_VERSION=7.0.1 xss-app
docker build -t astro-xss-7.1.0:fixture \
  --build-arg ASTRO_VERSION=7.1.0 --build-arg NODE_ADAPTER_VERSION=11.0.2 --build-arg REACT_ADAPTER_VERSION=7.0.1 xss-app
docker build -t astro-xss-dev-5.15.5:fixture --build-arg ASTRO_VERSION=5.15.5 xss-dev-app
docker build -t astro-xss-dev-5.15.6:fixture --build-arg ASTRO_VERSION=5.15.6 xss-dev-app
