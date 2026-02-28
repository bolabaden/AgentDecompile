# BuildKit can be enabled, but this Dockerfile avoids requiring an external Dockerfile frontend image.
# (No #syntax directive and no RUN --mount cache syntax, so builds work even when docker.io is unreachable.)
#   Linux/mac:  export DOCKER_BUILDKIT=1
#   PowerShell: $Env:DOCKER_BUILDKIT="1"
#   Cmd:        set DOCKER_BUILDKIT=1
#
# MCP-only image: one container runs only AgentDecompile MCP (8080).
# For the all-in-one (Ghidra server + BSim + MCP) image, use Dockerfile.aio.
FROM alpine:latest AS build

# --- Layer 1: env and args (change rarely; keep before any RUN so cache is stable) ---
ARG GHIDRA_HOME="/ghidra"
ENV GHIDRA_HOME=${GHIDRA_HOME}
ARG GHIDRA_INSTALL_DIR="/ghidra"
ENV GHIDRA_INSTALL_DIR=${GHIDRA_INSTALL_DIR}
ARG JAVA_HOME="/usr/lib/jvm/java-21-openjdk"
ENV JAVA_HOME=${JAVA_HOME}
ARG LD_LIBRARY_PATH="${JAVA_HOME}/lib/:/${JAVA_HOME}/lib/server/"
ENV LD_LIBRARY_PATH=${LD_LIBRARY_PATH}

# Optional: GHIDRA_VERSION (e.g. 12.0.3) pins the release; omit to use latest.
ARG GHIDRA_VERSION=""
ENV GHIDRA_VERSION=${GHIDRA_VERSION}

ARG GHIDRA_OWNER="NationalSecurityAgency"
ENV GHIDRA_OWNER=${GHIDRA_OWNER}
ARG GHIDRA_REPO="ghidra"
ENV GHIDRA_REPO=${GHIDRA_REPO}
ENV GHIDRA_GITHUB_API="https://api.github.com/repos/${GHIDRA_OWNER}/${GHIDRA_REPO}"

ARG GHIDRA_USER="ghidra"
ENV GHIDRA_USER=${GHIDRA_USER}
ARG GHIDRA_GROUP="ghidra"
ENV GHIDRA_GROUP=${GHIDRA_GROUP}
ARG PUID="1001"
ENV PUID=${PUID}
ARG PGID="1001"
ENV PGID=${PGID}

# --- Layer 2: system packages + fonts (cached unless this RUN or above changes) ---
# Use dl.alpinelinux.org to avoid "No such file or directory" under QEMU; install packages then create user/group
RUN \
    set -eux; \
    run() { echo "\n\nSTEP: $*"; "$@"; _r=$?; if [ "$_r" -ne 0 ]; then echo "FAILED (exit $_r): $*"; exit "$_r"; fi; }; \
    run cat /etc/apk/repositories; \
    run apk update; \
    run apk add --no-cache \
        shadow \
        openjdk21 \
        bash \
        gcompat \
        unzip \
        curl \
        jq \
        python3 \
        py3-pip \
        python3-dev \
        git \
        gradle \
        fontconfig \
        msttcorefonts-installer \
        linux-headers \
        libressl-dev \
        powershell \
    ; \
    run addgroup -g ${PGID} -S ${GHIDRA_GROUP}; \
    run adduser -u ${PUID} -S ${GHIDRA_USER} -G ${GHIDRA_GROUP}; \
    run update-ms-fonts; \
    run fc-cache -f

# --- Layer 3: download Ghidra (cached unless GHIDRA_VERSION/API or above changes) ---
RUN set -eux; \
    if [ -n "${GHIDRA_VERSION}" ]; then \
        API_URL="${GHIDRA_GITHUB_API}/releases/tags/Ghidra_${GHIDRA_VERSION}_build"; \
    else \
        API_URL="${GHIDRA_GITHUB_API}/releases/latest"; \
    fi; \
    echo "Fetching Ghidra release from ${API_URL}"; \
    BODY="$(curl -sSL -H 'Accept: application/vnd.github+json' "${API_URL}")"; \
    DOWNLOAD_URL="$(echo "${BODY}" | jq -r '.assets[] | select(.name | test("\\.zip$")) | select(.name | test("PUBLIC")) | .browser_download_url' | head -n 1)"; \
    if [ -z "${DOWNLOAD_URL}" ] || [ "${DOWNLOAD_URL}" = "null" ]; then \
        echo "Could not determine Ghidra download URL from ${API_URL}"; exit 1; \
    fi; \
    echo "Downloading ${DOWNLOAD_URL}"; \
    curl -sSL -o /tmp/ghidra.zip "${DOWNLOAD_URL}"; \
    unzip -q -d /tmp/ghidra_extract /tmp/ghidra.zip; \
    mv /tmp/ghidra_extract/ghidra_* ${GHIDRA_HOME}; \
    rm -f /tmp/ghidra.zip; \
    rm -rf /tmp/ghidra_extract

# build postgres and install pyghidra
RUN set -eux; \
        apk add --no-cache g++ gcc musl-dev make bison flex zlib-dev readline-dev perl; \
        ${GHIDRA_HOME}/Ghidra/Features/BSim/support/make-postgres.sh; \
        ARCH="$(uname -m)"; \
        case "${ARCH}" in \
            x86_64) OSDIR="linux_x86_64" ;; \
            aarch64) OSDIR="linux_arm_64" ;; \
            *) OSDIR="linux_${ARCH}" ;; \
        esac; \
        test -x "${GHIDRA_HOME}/Ghidra/Features/BSim/build/os/${OSDIR}/postgresql/bin/postgres"; \
        python3 -m venv ${GHIDRA_HOME}/venv; \
        ${GHIDRA_HOME}/venv/bin/python3 -m pip install --no-index -f ${GHIDRA_HOME}/Ghidra/Features/PyGhidra/pypkg/dist pyghidra; \
        apk del g++ gcc musl-dev make bison flex zlib-dev readline-dev perl || true; \
        mkdir ${GHIDRA_HOME}/repositories; \
        mkdir ${GHIDRA_HOME}/bsim_datadir

# --- Layer 3b: build native decompiler/sleigh ONLY on arm64 (x86_64 ships prebuilt) ---
# The Ghidra PUBLIC release includes prebuilt linux_x86_64 binaries but NOT linux_arm_64.
# On arm64: install C++ toolchain, build from source, then remove toolchain to shrink layer.
# On x86_64: no-op — the release zip already has the binaries.
RUN set -eux; \
    ARCH="$(uname -m)"; \
    OSDIR="linux_$(echo "${ARCH}" | sed 's/aarch64/arm_64/' | sed 's/x86_64/x86_64/')"; \
    NATIVE_DIR="${GHIDRA_HOME}/Ghidra/Features/Decompiler/os/${OSDIR}"; \
    if [ -d "${NATIVE_DIR}" ] && [ -f "${NATIVE_DIR}/decompile" ]; then \
        echo "Native decompiler already present at ${NATIVE_DIR} — skipping build (${ARCH})"; \
    elif [ "${ARCH}" = "x86_64" ]; then \
        echo "ERROR: x86_64 prebuilt binaries missing from Ghidra release — this should not happen"; \
        exit 1; \
    else \
        echo "Platform ${ARCH} (${OSDIR}): prebuilt binaries not included in Ghidra release — building from source..."; \
        apk add --no-cache g++ gcc musl-dev bison flex make zlib-dev readline-dev; \
        cd ${GHIDRA_HOME}/Ghidra/Features/Decompiler/src/decompile/cpp; \
        mkdir -p ghi_opt sla_opt; \
        make OSDIR="${OSDIR}" ARCH_TYPE="" ghidra_opt sleigh_opt; \
        mkdir -p "${NATIVE_DIR}"; \
        cp ghidra_opt "${NATIVE_DIR}/decompile"; \
        cp sleigh_opt "${NATIVE_DIR}/sleigh"; \
        chmod +x "${NATIVE_DIR}/decompile" "${NATIVE_DIR}/sleigh"; \
        echo "Native binaries installed to ${NATIVE_DIR}"; \
        make clean; \
        echo "Removing C++ build toolchain to reduce image size..."; \
        apk del g++ gcc musl-dev bison flex make zlib-dev readline-dev || true; \
    fi

# --- Layer 4: source (invalidates from here when you change code) ---
COPY . /src/agentdecompile
WORKDIR /src/agentdecompile

# --- Layer 4b: build/install AgentDecompile Ghidra extension ---
RUN set -eux; \
        if [ -f ./build.gradle ] || [ -f ./build.gradle.kts ] || [ -f ./settings.gradle ] || [ -f ./settings.gradle.kts ]; then \
            gradle clean buildExtension; \
            EXTENSION_ZIP="$(find . -maxdepth 4 -type f -path '*/dist/*.zip' | head -n 1)"; \
            test -n "${EXTENSION_ZIP}"; \
            mkdir -p /ghidra/Ghidra/Extensions; \
            unzip -q "${EXTENSION_ZIP}" -d /ghidra/Ghidra/Extensions/; \
        else \
            echo "No Gradle build files found; skipping extension build"; \
        fi

# --- Layer 5: install AgentDecompile Python package into venv ---
ARG SETUPTOOLS_SCM_PRETEND_VERSION_FOR_AGENTDECOMPILE=0.0.0
ENV SETUPTOOLS_SCM_PRETEND_VERSION_FOR_AGENTDECOMPILE=${SETUPTOOLS_SCM_PRETEND_VERSION_FOR_AGENTDECOMPILE}
ARG CHROMADB_VERSION=1.5.2
ENV CHROMADB_VERSION=${CHROMADB_VERSION}
RUN set -eux; \
    ARCH="$(uname -m)"; \
    if [ "${ARCH}" = "aarch64" ]; then \
        apk add --no-cache \
            --repository=https://dl-cdn.alpinelinux.org/alpine/edge/main \
            --repository=https://dl-cdn.alpinelinux.org/alpine/edge/community \
            py3-onnxruntime \
        ; \
    fi; \
    apk add --no-cache --virtual .chromadb-build \
        cargo \
        rust \
        gcc \
        g++ \
        musl-dev \
        python3-dev \
        libffi-dev \
    ; \
    ${GHIDRA_HOME}/venv/bin/python3 -m pip install --no-cache-dir --upgrade pip setuptools wheel; \
    ${GHIDRA_HOME}/venv/bin/python3 -m pip install --no-cache-dir \
        --prefer-binary \
        chromadb==${CHROMADB_VERSION} \
        /src/agentdecompile \
    ; \
    apk del .chromadb-build || true

FROM alpine:latest AS runtime

# --- Runtime env/args ---
ARG JAVA_HOME="/usr/lib/jvm/java-21-openjdk"
ENV JAVA_HOME=${JAVA_HOME}
ARG LD_LIBRARY_PATH="${JAVA_HOME}/lib/:${JAVA_HOME}/lib/server/"
ENV LD_LIBRARY_PATH=${LD_LIBRARY_PATH}
ARG GHIDRA_HOME="/ghidra"
ENV GHIDRA_HOME=${GHIDRA_HOME}
ARG GHIDRA_INSTALL_DIR="/ghidra"
ENV GHIDRA_INSTALL_DIR=${GHIDRA_INSTALL_DIR}

ARG AGENT_DECOMPILE_HOST="0.0.0.0"
ENV AGENT_DECOMPILE_HOST=${AGENT_DECOMPILE_HOST}
ARG AGENT_DECOMPILE_PROJECT_PATH=""
ENV AGENT_DECOMPILE_PROJECT_PATH=${AGENT_DECOMPILE_PROJECT_PATH}
ARG AGENT_DECOMPILE_CONFIG_FILE=""
ENV AGENT_DECOMPILE_CONFIG_FILE=${AGENT_DECOMPILE_CONFIG_FILE}

ARG GHIDRA_USER="ghidra"
ENV GHIDRA_USER=${GHIDRA_USER}
ARG GHIDRA_GROUP="ghidra"
ENV GHIDRA_GROUP=${GHIDRA_GROUP}
ARG PUID="1001"
ENV PUID=${PUID}
ARG PGID="1001"
ENV PGID=${PGID}

# --- Runtime packages (cached unless this RUN or above changes) ---
# MCP-only runtime: Java + Python venv artifacts + shell.
RUN \
    set -eux; \
    run() { echo "\n\nSTEP: $*"; "$@"; _r=$?; if [ "$_r" -ne 0 ]; then echo "FAILED (exit $_r): $*"; exit "$_r"; fi; }; \
    run cat /etc/apk/repositories; \
    run apk update; \
    run apk add --no-cache \
        shadow \
        openjdk21 \
        bash \
        gcompat \
    python3 \
    openssl \
    libstdc++ \
        musl-locales \
                musl-locales-lang \
    ; \
    run addgroup -g ${PGID} -S ${GHIDRA_GROUP}; \
    run adduser -u ${PUID} -S ${GHIDRA_USER} -G ${GHIDRA_GROUP}

WORKDIR ${GHIDRA_HOME}
COPY --from=build ${GHIDRA_HOME} ${GHIDRA_HOME}
RUN set -eux; \
    mkdir -p ${GHIDRA_HOME}/docker; \
    printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -euo pipefail' \
    '' \
    'ARGS=(' \
    '    -t streamable-http' \
    '    --host "${AGENT_DECOMPILE_HOST:-0.0.0.0}"' \
    '    --port "${AGENT_DECOMPILE_PORT:-8080}"' \
    ')' \
    '' \
    'if [[ -n "${AGENT_DECOMPILE_PROJECT_PATH:-}" ]]; then' \
    '    ARGS+=(--project-path "${AGENT_DECOMPILE_PROJECT_PATH}")' \
    'fi' \
    '' \
    'if [[ -n "${AGENT_DECOMPILE_CONFIG_FILE:-}" ]]; then' \
    '    ARGS+=(--config "${AGENT_DECOMPILE_CONFIG_FILE}")' \
    'fi' \
    '' \
    'exec /ghidra/venv/bin/agentdecompile-server "${ARGS[@]}"' \
    > ${GHIDRA_HOME}/docker/start-mcp.sh; \
    sed -i 's/\r$//' ${GHIDRA_HOME}/docker/start-mcp.sh; \
    chmod +x ${GHIDRA_HOME}/docker/start-mcp.sh; \
    mkdir -p /work /projects; \
    chown -R ${GHIDRA_USER}:${GHIDRA_GROUP} ${GHIDRA_HOME} /work /projects

USER ${GHIDRA_USER}

ARG AGENT_DECOMPILE_PORT="8080"
ENV AGENT_DECOMPILE_PORT=${AGENT_DECOMPILE_PORT}
EXPOSE ${AGENT_DECOMPILE_PORT}

ENTRYPOINT ["/bin/bash", "/ghidra/docker/start-mcp.sh"]
