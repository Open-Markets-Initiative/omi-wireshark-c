# Build image for compiling the generated dissectors into Wireshark.
# Built and published by .github/workflows/build-image.yml whenever this file changes.

FROM debian:trixie-slim

# Wireshark's required build dependencies, and the optional ones its
# configure step looks for. Anything cmake reports as missing belongs here.
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        build-essential \
        cmake \
        ninja-build \
        pkg-config \
        flex \
        bison \
        python3 \
        git \
        ca-certificates \
        libglib2.0-dev \
        libpcap-dev \
        libgcrypt20-dev \
        libc-ares-dev \
        libspeexdsp-dev \
        libxml2-dev \
        liblz4-dev \
        libzstd-dev \
        libsnappy-dev \
        libnghttp2-dev \
        libbrotli-dev \
        libssh-dev \
        libmaxminddb-dev && \
    rm -rf /var/lib/apt/lists/*
