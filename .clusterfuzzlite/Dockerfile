# ClusterFuzzLite build image: the fuzz targets in fuzz/ (cargo-fuzz, libFuzzer).
# Pinned by digest; Dependabot (docker) proposes updates.
FROM gcr.io/oss-fuzz-base/base-builder-rust@sha256:2216f0ac0a289a0e8974917779c3f744c354067dd81e0c8f2fc53bc1a9a573db

# Headers the GUI dependencies may need to build on Linux (same list as ci.yml). The fuzz
# targets never open a window, and these crates load their libraries with dlopen.
RUN apt-get update && apt-get install -y --no-install-recommends \
    libxkbcommon-dev libwayland-dev libx11-dev libgl1-mesa-dev \
    libxcb-render0-dev libxcb-shape0-dev libxcb-xfixes0-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*

# The image pins an older nightly than the code is written for (edition 2024, Rust 1.100
# in rust-toolchain.toml). Use the nightly the targets were built and run with locally
# (rustc 1.102.0-nightly 65ce8611f); bump it together with rust-toolchain.toml.
ENV RUSTUP_TOOLCHAIN=nightly-2026-11-19
RUN rustup toolchain install nightly-2026-11-19 --profile minimal

COPY . $SRC/network-scope
WORKDIR $SRC/network-scope
COPY .clusterfuzzlite/build.sh $SRC/
