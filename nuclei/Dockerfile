FROM python:3.13-alpine

ENV NUCLEI_VERSION=3.4.3
ENV NUCLEI_URL=https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip

WORKDIR /opt/common

COPY --from=common ./ ./

WORKDIR /opt/openaev-injector-nuclei

# Copy the injector
COPY ./ ./

# Install Python modules
RUN apk update && apk upgrade && \
    apk --no-cache add \
    curl \
    git \
    build-base \
    libmagic \
    libffi-dev \
    libxslt \
    libxslt-dev \
    libxml2 \
    libxml2-dev \
    && rm -rf /var/cache/apk/*

# Nuclei Installation
RUN curl -sSL "$NUCLEI_URL" -o nuclei.zip && \
    unzip nuclei.zip -d /usr/local/bin && \
    rm -rf nuclei.zip

# Installation Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Expose and entrypoint
CMD ["python3", "-m", "nuclei.openaev_nuclei"]
