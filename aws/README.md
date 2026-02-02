# OpenAEV AWS Injector

## Overview

The OpenAEV injector allows security teams to perform comprehensive AWS security assessments directly from OpenAEV.

## Features

### Supported AWS Modules

The injector provides contracts for the following AWS capabilities:

#### Attack Actions
Some contracts perform active attacks rather than passive enumeration:
- **IAM Create User**: Creates a new IAM user for persistence (marked as Attack)
- These actions modify the target AWS environment and should be used with caution

#### Enumeration & Discovery
Most contracts perform read-only enumeration:

#### IAM (Identity and Access Management)
- **IAM Enumerate Permissions**: Discover IAM permissions for the current user/role
- **IAM Enumerate Users, Roles, Policies & Groups**: Comprehensive IAM enumeration
- **IAM Enumerate Roles**: List all IAM roles in the AWS account
- **IAM Privilege Escalation Scan**: Identify potential privilege escalation paths
- **IAM Get Account Password Policy**: Retrieve and analyze the AWS account password policy settings
- **IAM Create User (Attack)**: Create a new IAM user in the target AWS account (requires username parameter)

#### EC2 (Elastic Compute Cloud)
- **EC2 Enumerate**: Comprehensive EC2 enumeration including instances and security groups

#### S3 (Simple Storage Service)
- **S3 List Buckets**: List S3 buckets using AWS CLI integration
- **S3 Download Bucket**: Download contents from specific S3 buckets

#### Lambda
- **Lambda Enumerate**: List all Lambda functions and their configurations

#### CloudTrail
- **CloudTrail Download Event History**: Download and analyze CloudTrail events

#### VPC (Virtual Private Cloud)
- **VPC Enumerate Lateral Movement**: Map VPC configurations for lateral movement analysis

#### RDS (Relational Database Service)
- **RDS Enumerate**: List all RDS database instances

#### Secrets Manager
- **Secrets Enumerate**: Discover stored secrets and their metadata

#### Systems Manager (SSM)
- **SSM Download Parameters**: Download SSM Parameter Store entries

#### Organizations
- **Organizations Enumerate**: Map AWS Organizations structure

#### Additional Services
- **EBS Enumerate Snapshots**: Enumerate EBS snapshots (unauthenticated)
- **DynamoDB Enumerate**: List DynamoDB tables
- **ECR Enumerate**: List ECR repositories
- **ECS Enumerate**: Enumerate ECS clusters
- **EKS Enumerate**: Enumerate EKS clusters
- **GuardDuty List Findings**: List GuardDuty security findings
- **Cognito Enumerate**: Enumerate Cognito user pools
- **Glue Enumerate**: List Glue databases
- **Route53 Enumerate**: List Route53 hosted zones
- **SNS Enumerate**: List SNS topics

### AWS CLI Integration

The injector supports direct AWS CLI command execution through AWS, enabling:
- Custom S3 operations (`s3 ls`, `s3 cp`, etc.)
- Any AWS CLI command for services not directly supported by AWS modules
- Flexible command customization through the contract interface

### Supported AWS Regions

The injector supports all current AWS regions including:

**North America**: US East (N. Virginia, Ohio), US West (N. California, Oregon), Canada (Central, Calgary)

**Europe**: Ireland, London, Paris, Frankfurt, Zurich, Stockholm, Milan, Spain

**Asia Pacific**: Tokyo, Seoul, Singapore, Sydney, Mumbai, Hong Kong, Jakarta, Melbourne, Hyderabad, Kuala Lumpur, Bangkok, Osaka

**Other Regions**: Middle East (Bahrain, UAE, Tel Aviv), Africa (Cape Town), South America (São Paulo), China (Beijing, Ningxia), AWS GovCloud (US-East, US-West)

## Configuration variables

There are a number of configuration options, which are set either in `docker-compose.yml` (for Docker) or
in `config.yml` (for manual deployment).

### OpenAEV environment variables

Below are the parameters you'll need to set for OpenAEV:

| Parameter     | config.yml | Docker environment variable | Mandatory | Description                                          |
|---------------|------------|-----------------------------|-----------|------------------------------------------------------|
| OpenAEV URL   | url        | `OPENAEV_URL`               | Yes       | The URL of the OpenAEV platform.                     |
| OpenAEV Token | token      | `OPENAEV_TOKEN`             | Yes       | The default admin token set in the OpenAEV platform. |

### Base injector environment variables

Below are the parameters you'll need to set for running the injector properly:

| Parameter        | config.yml | Docker environment variable | Default | Mandatory | Description                                                                            |
|------------------|------------|-----------------------------|---------|-----------|----------------------------------------------------------------------------------------|
| Injector ID      | id         | `INJECTOR_ID`               | /       | Yes       | A unique `UUIDv4` identifier for this injector instance.                               |
| Collector Name   | name       | `INJECTOR_NAME`             |         | Yes       | Name of the injector.                                                                  |
| Log Level        | log_level  | `INJECTOR_LOG_LEVEL`        | info    | Yes       | Determines the verbosity of the logs. Options are `debug`, `info`, `warn`, or `error`. |


## Deployment

### Using Docker

1. Build the Docker image:
```bash
cd aws
docker build --build-context injector_common=../injector_common -t openaev/injector-aws:latest .
```

2. Run with docker-compose:
```bash
docker-compose up -d
```

### Manual Installation

Create a file `config.yml` based on the provided `config.yml.sample`.

Replace the configuration variables with the appropriate configurations for
you environment.

The poetry package management system (version 2.1 or later) must also be available: https://python-poetry.org/

Install the environment:

**Production**:
```shell
# production environment
poetry install 
```

**Development** (note that you should also clone the [pyoaev](OpenAEV-Platform/client-python) repository [according to
these instructions](../README.md#simultaneous-development-on-pyoaev-and-an-injector))
```shell
# development environment
poetry install --extras dev
```

Then, start the collector:

```shell
poetry run python -m aws.openaev_aws
```

## Behaviour

1. **Deploy the Injector**: Start the AWS injector using Docker or manual installation
2. **Verify Registration**: Check that the injector appears in OpenAEV under Integrations > Injectors
3. **Create Injects**: Use the AWS contracts to create AWS security assessment injects
4. **Provide AWS Credentials**: Each inject requires:
   - AWS Access Key ID
   - AWS Secret Access Key
   - AWS Session Token (optional, for temporary credentials)
   - AWS Region (40+ regions supported)
5. **Execute and Monitor**: Run the injects and monitor results in OpenAEV

## Technical Details

### Session Management

The injector automatically manages AWS sessions:
- Creates a session named `openaev_session` if it doesn't exist
- Handles Windows-specific readline issues with non-interactive execution
- Properly manages AWS credentials through environment variables

### Error Handling

- Comprehensive error reporting with actual server error messages
- Proper handling of AWS execution failures and timeouts
- Signal handling for interrupted executions (SIGINT, SIGTERM)
- Fallback mechanisms for module execution

### Module Execution

- Direct AWS CLI integration for reliable execution
- AWS credentials passed via environment variables for security
- Non-interactive execution to prevent hanging on prompts
- Proper timeout handling (10 minutes default)

## Security Considerations

### AWS Credentials

- **Never hardcode AWS credentials** in configuration files
- Credentials are passed via environment variables, not stored
- Use temporary credentials with limited scope when possible
- Consider using AWS IAM roles for EC2 instances running the injector
- Rotate credentials regularly

### Permissions

The AWS credentials used with this injector should have appropriate read-only permissions for assessment purposes. Avoid using credentials with write/delete permissions unless specifically required for the assessment.

### Network Security

- Run the injector in a secure, isolated network segment
- Use TLS/SSL for communication with OpenAEV
- Implement proper firewall rules
- No debug logging in production to avoid credential exposure

## Development

### Adding New AWS Modules

To add support for additional AWS modules:

1. Add new contract IDs in `contracts_aws.py`
2. Define the contract with appropriate fields and outputs using the `make_contract` helper
3. Implement the execution method in `helpers/aws_executor.py`
4. Map the contract to the execution method in `openaev_aws.py`
5. Update the module name mapping in `_get_module_name()`

### Testing

Run the injector with info logging to test new modules:

```yaml
# In config.yml
injector:
  log_level: 'info'
```

## Troubleshooting

### Common Issues

1. **Injector not appearing in OpenAEV**
   - Verify network connectivity to OpenAEV
   - Check authentication token is valid
   - Review logs for connection errors

2. **AWS Authentication Failures**
   - Verify AWS credentials are correct
   - Check if credentials have necessary permissions
   - Ensure correct region is selected
   - Note: Some modules require specific permissions

3. **Module Execution Errors**
   - Check AWS is properly installed (`aws --help`)
   - Verify Python dependencies are up to date
   - Review execution logs for specific error messages
   - Ensure AWS session exists or can be created

4. **SIGINT/Readline Errors (Windows)**
   - This is handled automatically by the injector
   - Sessions are created using echo commands on Windows
   - If issues persist, try running AWS manually first

### Known Limitations

- Some AWS modules may not exist or have different names than expected
- S3 enumeration uses AWS CLI instead of a dedicated AWS module
- Windows environments may have readline compatibility issues (handled automatically)

### Logging

Logs are output to stdout/stderr in JSON format. When running in Docker, view logs with:

```bash
docker-compose logs -f injector-aws
```

Log format includes:
- Timestamp
- Log level (INFO, WARNING, ERROR)
- Logger name
- Message
- Exception info (when applicable)

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all AWS module names are verified against actual AWS modules
5. Submit a pull request

## License

This injector is released under the same license as OpenAEV. See the LICENSE file for details.

## Support

For issues and questions:
- OpenAEV Documentation: https://docs.openaev.io
- AWS Documentation: https://github.com/RhinoSecurityLabs/aws/wiki
- Submit issues: https://github.com/OpenAEV-Platform/injectors/issues

## Changelog

### Recent Updates
- Added support for 15+ additional AWS modules
- Implemented AWS CLI integration for S3 operations
- Expanded AWS regions support from 6 to 40+ regions
- Fixed Windows compatibility issues with AWS session management
- Improved error handling and reporting
- Removed debug logging for production security
- Optimized code structure with helper functions