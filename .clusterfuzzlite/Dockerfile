# ClusterFuzzLite build image: the fuzz targets in fuzz/ (cargo-fuzz, libFuzzer).
# Pinned by digest; Dependabot (docker) proposes updates.
FROM gcr.io/oss-fuzz-base/base-builder-rust@sha256:3428d0a90b1e7efbe2ba947bd1d0c9a70594986b4b6553804547f1fb24cfc92f

# Headers the GUI dependencies need to build on Linux (same list as ci.yml); the fuzz
# targets never open a window.
RUN apt-get update && apt-get install -y --no-install-recommends \
    libxkbcommon-dev libwayland-dev libx11-dev libgl1-mesa-dev \
    libxcb-render0-dev libxcb-shape0-dev libxcb-xfixes0-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*

# The code needs a newer compiler than the image's pinned nightly (Rust 1.100, edition 2024).
# This nightly is the one the targets were built and run with locally; bump it together with
# rust-toolchain.toml.
ENV RUSTUP_TOOLCHAIN=nightly-2026-11-18
RUN rustup toolchain install nightly-2026-11-18 --profile minimal

COPY . $SRC/network-scope
WORKDIR $SRC/network-scope
COPY .clusterfuzzlite/build.sh $SRC/
