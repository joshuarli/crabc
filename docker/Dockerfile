# Native Linux/AArch64 development image for crabc.
#
# Build it through scripts/dev.sh so Docker is always asked for linux/arm64.
# The base image and the reference musl source are pinned in
# compat/upstreams.toml as well as here, because Docker cannot consume TOML
# during FROM resolution.
FROM alpine:3.24.1@sha256:e7a1a92a5bfeee40966aea60f0796b0e7917cc35591542701834f03a68fa3d18

ARG RUST_TOOLCHAIN=nightly-2026-07-24
ARG MUSL_VERSION=1.2.6
ARG MUSL_SHA256=d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a
ARG LIBC_TEST_REV=123433158bf985d7eb3b4072e32121b9e32a1a1a

ENV RUSTUP_HOME=/opt/rustup \
    CARGO_HOME=/opt/cargo \
    PATH=/opt/cargo/bin:/opt/musl-1.2.6/bin:${PATH}

# The image contains only development tooling and pinned reference sources.
# crabc itself is bind-mounted by scripts/dev.sh, keeping image rebuilds
# independent from Rust source changes.
RUN apk add --no-cache \
        bash \
        binutils \
        build-base \
        ca-certificates \
        clang \
        coreutils \
        curl \
        git \
        lld \
        linux-headers \
        llvm \
        python3 \
        rustup \
        strace \
        tar \
        xz \
    # Alpine packages the bootstrap binary as rustup-init rather than rustup.
    && rustup-init -y --profile minimal --default-toolchain "${RUST_TOOLCHAIN}" \
    && rustup component add rust-src llvm-tools

# Alpine's system musl is intentionally not the oracle. Build the pinned
# upstream release under /opt so neither libc nor ld-musl in the container is
# replaced. musl-gcc then lets the existing integration tests use that oracle.
RUN curl --fail --location --retry 3 --output /tmp/musl.tar.gz \
        "https://musl.libc.org/releases/musl-${MUSL_VERSION}.tar.gz" \
    && echo "${MUSL_SHA256}  /tmp/musl.tar.gz" | sha256sum -c - \
    && tar -C /tmp -xzf /tmp/musl.tar.gz \
    && cd "/tmp/musl-${MUSL_VERSION}" \
    && ./configure \
        --prefix="/opt/musl-${MUSL_VERSION}" \
        --syslibdir="/opt/musl-${MUSL_VERSION}/lib" \
    && make -s -j"$(getconf _NPROCESSORS_ONLN)" \
    && make -s install \
    && sh tools/musl-gcc.specs.sh \
        "/opt/musl-${MUSL_VERSION}/include" \
        "/opt/musl-${MUSL_VERSION}/lib" \
        "/opt/musl-${MUSL_VERSION}/lib/ld-musl-aarch64.so.1" \
        > "/opt/musl-${MUSL_VERSION}/lib/musl-gcc.specs" \
    # Alpine's GCC specs require this compiler-support archive even when musl
    # supplies the runtime. Keeping it with the reference libraries preserves
    # their search priority over Alpine's system libc.
    && cp /usr/lib/libssp_nonshared.a "/opt/musl-${MUSL_VERSION}/lib/" \
    && rm -rf /tmp/musl.tar.gz "/tmp/musl-${MUSL_VERSION}"

COPY docker/musl-gcc /usr/local/bin/musl-gcc
RUN chmod 0755 /usr/local/bin/musl-gcc

# libc-test is available to the harness without requiring a mutable checkout
# on the macOS host. The exact commit is recorded in compat/upstreams.toml.
RUN git clone https://repo.or.cz/libc-test.git /opt/libc-test \
    && cd /opt/libc-test \
    && git checkout --detach "${LIBC_TEST_REV}" \
    && test "$(git rev-parse HEAD)" = "${LIBC_TEST_REV}" \
    && rm -rf .git

WORKDIR /workspace
CMD ["bash"]
