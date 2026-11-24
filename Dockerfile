# seccheck sandbox: the attack library runs in here with --network none, no capabilities, read-only code mount.
FROM debian:stable-slim
RUN apt-get update && apt-get install -y --no-install-recommends python3 procps file && rm -rf /var/lib/apt/lists/*
WORKDIR /tmp
