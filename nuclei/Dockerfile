FROM python:3.13-alpine AS builder

RUN apk update && apk upgrade

WORKDIR /opt/injector_common
COPY --from=injector_common ./ ./

# poetry version available on Ubuntu 24.04
RUN pip3 install poetry==2.1.3

ARG installdir=/opt/injector
ADD . ${installdir}
WORKDIR ${installdir}
RUN poetry build

FROM python:3.13-alpine AS runner

WORKDIR /opt/injector_common
COPY --from=injector_common ./ ./

ARG installdir=/opt/injector
WORKDIR ${installdir}
COPY --from=builder ${installdir} ${installdir}
RUN pip3 install --no-cache-dir "$(ls dist/*.whl)"

# Declare the build argument
ARG PYOAEV_GIT_BRANCH_OVERRIDE

RUN if [[ ${PYOAEV_GIT_BRANCH_OVERRIDE} ]] ; then \
        echo "Forcing specific version of client-python" && \
        apk add --no-cache git && \
        pip install pip3-autoremove && \
        pip-autoremove pyoaev -y && \
        pip install git+https://github.com/OpenAEV-Platform/client-python@${PYOAEV_GIT_BRANCH_OVERRIDE} ; \
    fi

# get nuclei from above
ENV NUCLEI_VERSION=3.4.3
ENV NUCLEI_URL=https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip
ADD ${NUCLEI_URL} /tmp
RUN unzip /tmp/nuclei_${NUCLEI_VERSION}_linux_amd64.zip -d /usr/local/bin/

CMD ["python3", "-m", "nuclei.openaev_nuclei"]
