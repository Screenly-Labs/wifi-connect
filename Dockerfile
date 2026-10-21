# syntax=docker/dockerfile:1.27.1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
#
# The syntax line names an image that BuildKit pulls and runs to parse this
# file, in the release job that pushes to GHCR, so it is pinned by digest
# like every other build image. 1.27.1 is what `docker/dockerfile:1`
# resolved to when pinned; bump tag and digest together.
#
# Assembles the release image from binaries already cross-compiled by CI.
# There is deliberately no compiler in here.
#
# Building Rust for arm under QEMU inside buildx is the single biggest time
# sink in multi-arch Rust: a 10-30x slowdown, routine multi-hour builds, and
# the occasional ICE. Building once with `cross` and then COPYing means the
# image build is a file copy, every architecture ships the *same* bytes, and
# no layer cache is needed at all.
#
# See Dockerfile.selfcontained for a single-arch `docker build .` that needs
# no CI — a developer convenience, not the release path.

FROM scratch

ARG TARGETARCH
ARG TARGETVARIANT

# dist/ holds wifi-connect-amd64, wifi-connect-arm64 and wifi-connect-armv7.
# ${TARGETARCH}${TARGETVARIANT} resolves to exactly those three names.
COPY --chmod=0755 dist/wifi-connect-${TARGETARCH}${TARGETVARIANT} /wifi-connect

# scratch has no shell, no CA bundle, no /etc/passwd and no tzdata. The
# binary is static musl, serves plain HTTP by design, and never resolves a
# hostname, so it needs none of them.
ENV WIFI_CONNECT_LOG_FORMAT=json \
    TZ=UTC

LABEL org.opencontainers.image.title="wifi-connect" \
      org.opencontainers.image.description="Minimal tool for joining WiFi networks" \
      org.opencontainers.image.source="https://github.com/Screenly-Labs/wifi-connect" \
      org.opencontainers.image.licenses="Apache-2.0"

EXPOSE 80/tcp 53/udp 67/udp

ENTRYPOINT ["/wifi-connect"]
