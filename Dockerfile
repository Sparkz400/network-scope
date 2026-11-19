# Container image of the Network Scope CLI (network-scope-cli), published to
# ghcr.io/sparkz400/network-scope by .github/workflows/release.yml.
#
# Base images are pinned by digest; Dependabot (docker ecosystem, directory /) proposes updates.
# The compiler version comes from rust-toolchain.toml (`rustup toolchain install` below), so a
# toolchain bump still builds if this tag lags behind; keep the tag in step to avoid the download.

FROM rust:1.100.0-slim-trixie@sha256:6f14b2b4b278ec0d50aa1d69541c304ce0f95e0f6268487aa9924af1c2e9aebe AS build

# The GUI crates are compiled into both binaries, so the build needs the same development
# packages as CI (.github/workflows/ci.yml). pkg-config is preinstalled on the CI runners only.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        pkg-config libxkbcommon-dev libwayland-dev libx11-dev libgl1-mesa-dev \
        libxcb-render0-dev libxcb-shape0-dev libxcb-xfixes0-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY rust-toolchain.toml ./
RUN rustup toolchain install

COPY . .
RUN cargo build --release --locked --bin network-scope-cli \
    && cp target/release/network-scope-cli /network-scope-cli

FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2

# Runtime needs: the binary links only glibc, libm and libgcc_s (all in the base image). The
# X11/Wayland/GL/xkbcommon libraries of the GUI are dlopen()ed when a window opens, which the
# CLI never does. libpcap is also loaded at run time (libpcap.so.0.8 from libpcap0.8t64) and is
# only needed for capture features (SYN, ARP sweep, listen, dcp, TCP traceroute).
# ca-certificates for webhook alerts over HTTPS.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libpcap0.8t64 ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --user-group --home-dir /data --create-home --shell /usr/sbin/nologin scanner

COPY --from=build /network-scope-cli /usr/local/bin/network-scope-cli

LABEL org.opencontainers.image.title="Network Scope CLI" \
      org.opencontainers.image.description="Network scanner and analysis tool (command-line interface)" \
      org.opencontainers.image.source="https://github.com/Sparkz400/network-scope" \
      org.opencontainers.image.url="https://sparkz400.github.io/network-scope/" \
      org.opencontainers.image.documentation="https://sparkz400.github.io/network-scope/installation.html" \
      org.opencontainers.image.licenses="MIT"

# The inventory database defaults to ./NetworkScope/inventory.sqlite on Linux; /data is owned by
# the unprivileged user and can be a volume (`-v network-scope:/data`).
USER scanner
WORKDIR /data
ENTRYPOINT ["network-scope-cli"]
# Without arguments the binary would try to open the desktop window.
CMD ["--help"]
