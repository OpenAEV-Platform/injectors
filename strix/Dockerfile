FROM python:3.13-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/injector_common
COPY --from=injector_common ./ ./

WORKDIR /
RUN git clone https://github.com/OpenAEV-Platform/client-python

RUN pip3 install poetry==2.3.2 \
    && poetry config installer.re-resolve false \
    && poetry config virtualenvs.create false

ARG installdir=/opt/injector
ADD . ${installdir}
WORKDIR ${installdir}
RUN poetry install

# Official Docker CLI image - source of a reliable, multi-arch `docker` client.
FROM docker:cli AS dockercli

FROM python:3.13-slim AS runner

# git + ca-certificates: git is needed for the optional pyoaev override install.
RUN apt-get update && apt-get install -y --no-install-recommends \
        git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/injector_common
COPY --from=injector_common ./ ./

ARG installdir=/opt/injector
WORKDIR ${installdir}
COPY --from=builder ${installdir} ${installdir}
COPY --from=builder /usr/local/lib/python3.13/site-packages /usr/local/lib/python3.13/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Docker CLI: Strix drives its sandbox by talking to a Docker daemon. The daemon
# itself is NOT run here - the host's socket is mounted in (see docker-compose.yml),
# so only the client is needed. Copied AFTER the /usr/local/bin COPY above so it
# is never clobbered, and verified at build time so a missing CLI fails the build
# instead of surfacing only at scan time.
COPY --from=dockercli /usr/local/bin/docker /usr/local/bin/docker
RUN docker --version

ARG PYOAEV_GIT_BRANCH_OVERRIDE
RUN if [ -n "${PYOAEV_GIT_BRANCH_OVERRIDE}" ] ; then \
        echo "Forcing specific version of client-python" && \
        pip install pip3-autoremove && \
        pip-autoremove pyoaev -y && \
        pip install git+https://github.com/OpenAEV-Platform/client-python@${PYOAEV_GIT_BRANCH_OVERRIDE} ; \
    fi

# Install the Strix agent (the offensive engine). Pinned; bump deliberately.
ARG STRIX_VERSION=1.6.2
RUN pip install --no-cache-dir "strix-agent==${STRIX_VERSION}"

CMD ["python3", "-m", "strix.openaev_strix"]
