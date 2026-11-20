FROM python:3.15-alpine AS builder

RUN apk --no-cache upgrade && apk --no-cache add git

WORKDIR /opt/injector_common
COPY --from=injector_common ./ ./

WORKDIR /
RUN git clone https://github.com/OpenAEV-Platform/client-python

RUN pip3 install --no-cache-dir -U pip certifi

# poetry version available on Ubuntu 24.04
RUN pip3 install --no-cache-dir poetry==2.3.2 \
    && poetry config installer.re-resolve false \
    && poetry config virtualenvs.create false

ARG installdir=/opt/injector
ADD . ${installdir}
WORKDIR ${installdir}
RUN poetry install

FROM python:3.15-alpine AS runner

RUN apk --no-cache upgrade
RUN pip install --no-cache-dir -U pip certifi

WORKDIR /opt/injector_common
COPY --from=injector_common ./ ./

ARG installdir=/opt/injector
WORKDIR ${installdir}
COPY --from=builder ${installdir} ${installdir}
COPY --from=builder /usr/local/lib/python3.13/site-packages /usr/local/lib/python3.13/site-packages

# Declare the build argument
ARG PYOAEV_GIT_BRANCH_OVERRIDE

RUN if [[ ${PYOAEV_GIT_BRANCH_OVERRIDE} ]] ; then \
        echo "Forcing specific version of client-python" && \
        apk add --no-cache git && \
        pip install --no-cache-dir pip3-autoremove && \
        pip-autoremove pyoaev -y && \
        pip install --no-cache-dir git+https://github.com/OpenAEV-Platform/client-python@${PYOAEV_GIT_BRANCH_OVERRIDE} ; \
    fi

# renovate: datasource=github-releases depName=projectdiscovery/subfinder
ARG SUBFINDER_VERSION=2.17.0
ARG SUBFINDER_URL=https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION}_linux_amd64.zip
ADD ${SUBFINDER_URL} /tmp
RUN unzip -o /tmp/subfinder_${SUBFINDER_VERSION}_linux_amd64.zip subfinder -d /usr/local/bin/ \
    && rm /tmp/subfinder_${SUBFINDER_VERSION}_linux_amd64.zip

# renovate: datasource=github-releases depName=projectdiscovery/dnsx
ARG DNSX_VERSION=1.3.1
ARG DNSX_URL=https://github.com/projectdiscovery/dnsx/releases/download/v${DNSX_VERSION}/dnsx_${DNSX_VERSION}_linux_amd64.zip
ADD ${DNSX_URL} /tmp
RUN unzip -o /tmp/dnsx_${DNSX_VERSION}_linux_amd64.zip dnsx -d /usr/local/bin/ \
    && rm /tmp/dnsx_${DNSX_VERSION}_linux_amd64.zip

CMD ["python3", "-m", "dns_enum.openaev_dns_enum"]
