# Build bulla, then ship it in a slim image with the toolchains it sandboxes.
# bulla builds its own isolation (user namespaces + seccomp + pivot_root) at runtime, so the
# container needs unprivileged user namespaces allowed. On Docker that usually means:
#     docker run --security-opt seccomp=unconfined ghcr.io/rars-oss/bulla \
#       run --work /work -- sh -c 'your-tests'
# (Docker's default seccomp profile blocks the clone/unshare namespace flags bulla uses; unconfined —
# or a profile that allows them — lets bulla build its cell. bulla then applies its own seccomp inside.)
FROM rust:1-slim AS build
WORKDIR /src
COPY . .
RUN cargo build --release -p bulla-cli && strip target/release/bulla

FROM debian:stable-slim
# Toolchains for the code bulla sandboxes, plus git for --seal-git. Extend as needed.
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential clang python3 git ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/bulla /usr/local/bin/bulla
RUN useradd -m runner
USER runner
WORKDIR /work
ENTRYPOINT ["bulla"]
CMD ["--help"]
