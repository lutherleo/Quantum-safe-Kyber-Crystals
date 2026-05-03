# Quantum-safe secure communication — build environment
# Pinned to a specific liboqs commit for reproducibility.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        cmake \
        ninja-build \
        git \
        ca-certificates \
        libssl-dev \
        python3 \
        python3-pip \
        python3-matplotlib \
        python3-numpy \
        tcpdump \
        iproute2 \
        netcat-openbsd \
        procps \
        coreutils \
    && rm -rf /var/lib/apt/lists/*

# Build liboqs (pinned commit on main, supports ML-KEM, ML-DSA, HQC, SLH-DSA).
ARG LIBOQS_REF=0.12.0
RUN git clone --depth 1 --branch ${LIBOQS_REF} https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs \
    && cmake -G Ninja -S /tmp/liboqs -B /tmp/liboqs/build \
        -DOQS_BUILD_ONLY_LIB=ON \
        -DBUILD_SHARED_LIBS=ON \
        -DOQS_DIST_BUILD=ON \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
    && cmake --build /tmp/liboqs/build --parallel \
    && cmake --install /tmp/liboqs/build \
    && ldconfig \
    && rm -rf /tmp/liboqs

WORKDIR /app

COPY CMakeLists.txt /app/
COPY src /app/src
COPY scripts /app/scripts

RUN cmake -G Ninja -S /app -B /app/build \
    && cmake --build /app/build --parallel

ENV PATH="/app/build:${PATH}"

CMD ["/bin/bash"]
