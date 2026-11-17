FROM haproxy:3.4.7-trixie
USER root
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 openssl python3 python3-h2 curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /project
