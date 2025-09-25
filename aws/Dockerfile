FROM python:3.13-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    gcc \
    python3-dev \
    libssl-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /opt/openbas-injector-aws

# Copy the injector source code
COPY src /opt/openbas-injector-aws

# Install Python dependencies
RUN pip3 install --no-cache-dir -r requirements.txt

# Verify AWS CLI is installed
RUN aws --version || echo "AWS CLI installation verification"

# Create AWS data directory
RUN mkdir -p /root/.local/share/aws

# Set environment variables for AWS
ENV AWS_HOME=/root/.local/share/aws

# Copy and set up entrypoint script
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh

# Set the entrypoint
ENTRYPOINT ["/entrypoint.sh"]
