# Builder
FROM python:3.13-alpine AS builder

# System dependencies required by netexec
RUN apk add --no-cache \
    gcc \
    musl-dev \
    libffi-dev \
    openssl-dev \
    cargo

# Install Poetry
RUN pip install --no-cache-dir poetry==2.1.3

# Copy shared injector code
WORKDIR /opt/injector_common
COPY --from=injector_common ./ ./

# Copy injector source
ARG installdir=/opt/injector
ADD . ${installdir}
WORKDIR ${installdir}

RUN poetry build && \
    for f in pyoaev-*.whl; do [ -f "$f" ] && cp "$f" dist/; done || true

# Runner
FROM python:3.13-alpine AS runner

# Runtime deps only
RUN apk add --no-cache \
    gcc \
    musl-dev \
    python3-dev \
    libffi-dev \
    openssl-dev \
    cargo \
    git

WORKDIR /opt/injector_common
COPY --from=injector_common ./ ./

ARG installdir=/opt/injector
WORKDIR ${installdir}
COPY --from=builder ${installdir}/dist ./dist

RUN pip3 install --no-cache-dir "$(ls dist/openaev_netexec_injector-*.whl)[prod]"

# Optional: override client-python version from git branch
ARG PYOAEV_GIT_BRANCH_OVERRIDE
RUN if [ -n "${PYOAEV_GIT_BRANCH_OVERRIDE}" ]; then \
        echo "Forcing specific version of client-python" && \
        pip install pip3-autoremove && \
        pip-autoremove pyoaev -y && \
        pip install git+https://github.com/OpenAEV-Platform/client-python@${PYOAEV_GIT_BRANCH_OVERRIDE} ; \
    fi

# Optional: override client-python from local wheel
RUN pyoaev_whl=$(ls dist/pyoaev-*.whl 2>/dev/null | head -1) && \
    if [ -n "$pyoaev_whl" ]; then \
        echo "Installing local pyoaev wheel: $pyoaev_whl" && \
        pip install --no-cache-dir --force-reinstall --no-deps "$pyoaev_whl" ; \
    fi

# Install netexec
RUN pip install --no-cache-dir git+https://github.com/Pennyw0rth/NetExec.git

# Default command
CMD ["python3", "-m", "netexec.openaev_netexec"]
