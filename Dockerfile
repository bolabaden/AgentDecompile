# syntax=docker/dockerfile:1
# BuildKit enables cache mounts (--mount=type=cache) for apk and Gradle. Required for cache mounts:
#   Linux/mac:  export DOCKER_BUILDKIT=1
#   PowerShell: $Env:DOCKER_BUILDKIT="1"
#   Cmd:        set DOCKER_BUILDKIT=1
# Podman on Windows: set the same env var so podman compose build / docker compose build use it.
FROM alpine:3 AS build

# --- Layer 1: env and args (change rarely; keep before any RUN so cache is stable) ---
ENV GHIDRA_HOME=/ghidra
ENV GHIDRA_INSTALL_DIR=/ghidra
ENV JAVA_HOME=/usr/lib/jvm/java-21-openjdk
ENV LD_LIBRARY_PATH=/usr/lib/jvm/java-21-openjdk/lib/:/usr/lib/jvm/java-21-openjdk/lib/server/

# Optional: GHIDRA_VERSION (e.g. 12.0.3) pins the release; omit to use latest.
ARG GHIDRA_VERSION=
ENV GHIDRA_VERSION=${GHIDRA_VERSION}

ARG GHIDRA_OWNER=NationalSecurityAgency
ENV GHIDRA_OWNER=${GHIDRA_OWNER}
ARG GHIDRA_REPO=ghidra
ENV GHIDRA_REPO=${GHIDRA_REPO}
ENV GHIDRA_GITHUB_API=https://api.github.com/repos/${GHIDRA_OWNER}/${GHIDRA_REPO}

ARG GHIDRA_USER=ghidra
ARG GHIDRA_GROUP=ghidra
ARG PUID=1001
ARG PGID=1001
ENV GHIDRA_USER=${GHIDRA_USER}
ENV GHIDRA_GROUP=${GHIDRA_GROUP}
ENV PUID=${PUID}
ENV PGID=${PGID}

# --- Layer 2: system packages + fonts (cached unless this RUN or above changes) ---
# Use dl.alpinelinux.org to avoid "No such file or directory" under QEMU; install packages then create user/group
RUN --mount=type=cache,target=/var/cache/apk \
    set -eux; \
    run() { echo "\n\nSTEP: $*"; "$@"; _r=$?; if [ "$_r" -ne 0 ]; then echo "FAILED (exit $_r): $*"; exit "$_r"; fi; }; \
    run cat /etc/apk/repositories; \
    run apk update; \
    run apk add --no-cache \
        shadow \
        openjdk21 \
        bash \
        gcompat \
        gradle \
        unzip \
        curl \
        jq \
        python3 \
        py3-pip \
        git \
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
    mv /tmp/ghidra_extract/ghidra_* /ghidra; \
    rm -f /tmp/ghidra.zip; \
    rm -rf /tmp/ghidra_extract

# --- Layer 4: source (invalidates from here when you change code) ---
COPY . /src/agentdecompile
WORKDIR /src/agentdecompile

# Disable Gradle daemon so native code does not run under QEMU (avoids SIGSEGV on arm64 when host is amd64)
ENV GRADLE_OPTS="-Dorg.gradle.daemon=false"

# --- Layer 5: build extension (reuses Gradle cache when layer runs again) ---
RUN --mount=type=cache,target=/root/.gradle \
    pwsh -NoProfile -NonInteractive -Command " \
    & ./build-and-install.ps1 -ProjectDir /src/agentdecompile -GhidraInstallDir /ghidra -GradlePath /usr/bin/gradle \
    "

FROM alpine:3 AS runtime

# --- Runtime env/args ---
ARG JAVA_HOME=/usr/lib/jvm/java-21-openjdk
ENV JAVA_HOME=${JAVA_HOME}
ARG LD_LIBRARY_PATH=${JAVA_HOME}/lib/:${JAVA_HOME}/lib/server/
ENV LD_LIBRARY_PATH=${LD_LIBRARY_PATH}
ARG GHIDRA_INSTALL_DIR=/ghidra
ENV GHIDRA_INSTALL_DIR=${GHIDRA_INSTALL_DIR}

ARG AGENT_DECOMPILE_HOST=0.0.0.0
ENV AGENT_DECOMPILE_HOST=${AGENT_DECOMPILE_HOST}
ARG AGENT_DECOMPILE_PORT=8080
ENV AGENT_DECOMPILE_PORT=${AGENT_DECOMPILE_PORT}
ARG AGENT_DECOMPILE_PROJECT_DIR=/projects
ENV AGENT_DECOMPILE_PROJECT_DIR=${AGENT_DECOMPILE_PROJECT_DIR}
ARG AGENT_DECOMPILE_PROJECT_NAME=agentdecompile
ENV AGENT_DECOMPILE_PROJECT_NAME=${AGENT_DECOMPILE_PROJECT_NAME}

ARG GHIDRA_USER=ghidra
ENV GHIDRA_USER=${GHIDRA_USER}
ARG GHIDRA_GROUP=ghidra
ENV GHIDRA_GROUP=${GHIDRA_GROUP}
ARG PUID=1001
ENV PUID=${PUID}
ARG PGID=1001
ENV PGID=${PGID}

# --- Runtime packages (cached unless this RUN or above changes) ---
# Use dl.alpinelinux.org to avoid QEMU fetch issues; install packages then create user/group
RUN --mount=type=cache,target=/var/cache/apk \
    set -eux; \
    run() { echo "\n\nSTEP: $*"; "$@"; _r=$?; if [ "$_r" -ne 0 ]; then echo "FAILED (exit $_r): $*"; exit "$_r"; fi; }; \
    run cat /etc/apk/repositories; \
    run apk update; \
    run apk add --no-cache \
        shadow \
        openjdk21 \
        bash \
        gcompat \
        openssl \
        openssh-client \
        xhost \
        musl-locales \
    ; \
    ( [ "$(uname -m)" = "x86_64" ] && run apk add --no-cache musl-locales-lang || true ); \
    run addgroup -g ${PGID} -S ${GHIDRA_GROUP}; \
    run adduser -u ${PUID} -S ${GHIDRA_USER} -G ${GHIDRA_GROUP}

WORKDIR /ghidra
COPY --from=build /ghidra /ghidra
COPY docker/entrypoint.sh /ghidra/docker/entrypoint.sh

RUN chmod +x /ghidra/docker/entrypoint.sh \
    && mkdir -p /work /projects \
    && chown -R ${GHIDRA_USER}:${GHIDRA_GROUP} /ghidra /work /projects

USER ${GHIDRA_USER}

EXPOSE ${AGENT_DECOMPILE_PORT}

ENTRYPOINT ["/bin/bash", "/ghidra/docker/entrypoint.sh"]
