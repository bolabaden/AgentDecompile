# syntax=docker/dockerfile:1
# BuildKit enables cache mounts (--mount=type=cache) for apk and Gradle. Required for cache mounts:
#   Linux/mac:  export DOCKER_BUILDKIT=1
#   PowerShell: $Env:DOCKER_BUILDKIT="1"
#   Cmd:        set DOCKER_BUILDKIT=1
#
# AIO image: one container runs Ghidra server (13100,13101,13102), BSim server (5432), and AgentDecompile MCP (8080).
# PyGhidra headless and Ghidra AnalyzeHeadless: docker exec -it <container> bash, then run there.
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
        python3-dev \
        git \
        fontconfig \
        msttcorefonts-installer \
        linux-headers \
        libressl-dev \
        powershell \
        g++ \
        gcc \
        musl-dev \
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
RUN ${GHIDRA_HOME}/Ghidra/Features/BSim/support/make-postgres.sh \
        && python3 -m venv ${GHIDRA_HOME}/venv \
        && ${GHIDRA_HOME}/venv/bin/python3 -m pip install --no-index -f ${GHIDRA_HOME}/Ghidra/Features/PyGhidra/pypkg/dist pyghidra \
		&& mkdir ${GHIDRA_HOME}/repositories \
        && mkdir ${GHIDRA_HOME}/bsim_datadir

# --- Layer 4: source (invalidates from here when you change code) ---
COPY . /src/agentdecompile
WORKDIR /src/agentdecompile

# Disable Gradle daemon so native code does not run under QEMU (avoids SIGSEGV on arm64 when host is amd64)
ENV GRADLE_OPTS="-Dorg.gradle.daemon=false"

# --- Layer 5: build extension (reuses Gradle cache when layer runs again) ---
RUN --mount=type=cache,target=/root/.gradle \
    pwsh -NoProfile -NonInteractive -Command " \
    & ./build-and-install.ps1 -ProjectDir /src/agentdecompile -GhidraInstallDir ${GHIDRA_INSTALL_DIR} -GradlePath /usr/bin/gradle \
    "

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
ARG AGENT_DECOMPILE_PROJECT_PATH="/projects/agentdecompile.gpr"
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
# Use dl.alpinelinux.org to avoid QEMU fetch issues; install packages then create user/group
# BSim PostgreSQL is built against LibreSSL in build stage; runtime needs libressl for libssl.so.60/libcrypto.so.57
#( grep -qE '^[^#].*community' /etc/apk/repositories ) || echo "https://dl-cdn.alpinelinux.org/alpine/v3.22/community" >> /etc/apk/repositories; \
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
        musl-locales-lang \
        supervisor \
        netcat-openbsd \
        readline \
        zlib \
        libressl \
    ; \
    run addgroup -g ${PGID} -S ${GHIDRA_GROUP}; \
    run adduser -u ${PUID} -S ${GHIDRA_USER} -G ${GHIDRA_GROUP}

WORKDIR ${GHIDRA_HOME}
COPY --from=build ${GHIDRA_HOME} ${GHIDRA_HOME}
# BSim PostgreSQL was linked against LibreSSL in build stage; copy exact libs so pg_ctl/initdb find libssl.so.60/libcrypto.so.57
RUN mkdir -p /opt/bsim-libs
COPY --from=build /usr/lib/libssl.so* /usr/lib/libcrypto.so* /opt/bsim-libs/
COPY docker/entrypoint.sh ${GHIDRA_HOME}/docker/entrypoint.sh
COPY docker/supervisord.conf ${GHIDRA_HOME}/docker/supervisord.conf
COPY docker/supervisor-wrap.sh docker/supervisor-wait-then-mcp.sh docker/run-bsim.sh ${GHIDRA_HOME}/docker/

RUN chmod +x ${GHIDRA_HOME}/docker/entrypoint.sh ${GHIDRA_HOME}/docker/supervisor-wrap.sh ${GHIDRA_HOME}/docker/supervisor-wait-then-mcp.sh ${GHIDRA_HOME}/docker/run-bsim.sh \
    && mkdir -p /work /projects \
    && chown -R ${GHIDRA_USER}:${GHIDRA_GROUP} ${GHIDRA_HOME} /work /projects

USER ${GHIDRA_USER}

ARG AGENT_DECOMPILE_PORT="8080"
ENV AGENT_DECOMPILE_PORT=${AGENT_DECOMPILE_PORT}
EXPOSE ${AGENT_DECOMPILE_PORT}
ARG GHIDRA_BSIM_PORT="5432"
ENV GHIDRA_BSIM_PORT=${GHIDRA_BSIM_PORT}
EXPOSE ${GHIDRA_BSIM_PORT}
ARG GHIDRA_SERVER_PORT1="13100"
ENV GHIDRA_SERVER_PORT1=${GHIDRA_SERVER_PORT1}
EXPOSE ${GHIDRA_SERVER_PORT1}
ARG GHIDRA_SERVER_PORT2="13101"
ENV GHIDRA_SERVER_PORT2=${GHIDRA_SERVER_PORT2}
EXPOSE ${GHIDRA_SERVER_PORT2}
ARG GHIDRA_SERVER_PORT3="13102"
ENV GHIDRA_SERVER_PORT3=${GHIDRA_SERVER_PORT3}
EXPOSE ${GHIDRA_SERVER_PORT3}

ENTRYPOINT ["/bin/bash", "/ghidra/docker/entrypoint.sh"]
