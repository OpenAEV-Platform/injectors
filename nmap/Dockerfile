FROM python:3.13-alpine

# Copy the injector
COPY src /opt/openaev-injector-nmap

# Install Python modules
# hadolint ignore=DL3003
RUN apk update && apk upgrade && \
    apk --no-cache add nmap jc git build-base libmagic libffi-dev libxslt libxslt-dev libxml2 libxml2-dev && \
    cd /opt/openaev-injector-nmap && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base

# Expose and entrypoint
COPY entrypoint2.sh /
RUN chmod +x /entrypoint2.sh
ENTRYPOINT ["/entrypoint2.sh"]
