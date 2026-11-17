ARG BASE=debian:13-slim
FROM ${BASE}
RUN apt-get update && apt-get install -y --no-install-recommends systemd systemd-sysv dbus passwd python3 ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
