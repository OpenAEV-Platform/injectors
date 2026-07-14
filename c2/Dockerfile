FROM python:3.13-alpine AS builder

ENV PIP_VERSION=25.0.1

RUN apk update && apk upgrade && apk add git curl

WORKDIR /opt/injector_common
COPY --from=injector_common ./ ./

WORKDIR /
RUN git clone https://github.com/OpenAEV-Platform/client-python

RUN curl -sS https://bootstrap.pypa.io/get-pip.py -o get-pip.py && \
    python3 get-pip.py pip==${PIP_VERSION} && \
    rm get-pip.py

RUN python3 -m pip install poetry==2.3.2 \
    && poetry config installer.re-resolve false \
    && poetry config virtualenvs.create false

ARG installdir=/opt/injector
ADD . ${installdir}
WORKDIR ${installdir}
RUN poetry install && \
    python3 -m pip install --no-cache-dir pip==${PIP_VERSION}

FROM python:3.13-alpine AS runner

ENV PIP_VERSION=25.0.1

WORKDIR /opt/injector_common
COPY --from=injector_common ./ ./

ARG installdir=/opt/injector
WORKDIR ${installdir}
COPY --from=builder ${installdir} ${installdir}
COPY --from=builder /usr/local/lib/python3.13/site-packages /usr/local/lib/python3.13/site-packages

ARG PYOAEV_GIT_BRANCH_OVERRIDE

RUN if [[ ${PYOAEV_GIT_BRANCH_OVERRIDE} ]] ; then \
        echo "Forcing specific version of client-python" && \
        apk add --no-cache git curl && \
        curl -sS https://bootstrap.pypa.io/get-pip.py -o get-pip.py && \
        python3 get-pip.py pip==${PIP_VERSION} && \
        rm get-pip.py && \
        pip install pip3-autoremove && \
        pip-autoremove pyoaev -y && \
        pip install git+https://github.com/OpenAEV-Platform/client-python@${PYOAEV_GIT_BRANCH_OVERRIDE} ; \
    fi

CMD ["python3", "-m", "c2_injector.openaev_c2"]
