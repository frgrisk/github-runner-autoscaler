# GitHub Runner Autoscaler

This project provides a Lambda function that launches ephemeral GitHub self-hosted
runners on EC2 in response to GitHub workflow job events. The function is deployed
using AWS SAM.

## Secret configuration

The function expects a GitHub personal access token (PAT) to be stored in AWS
Secrets Manager. Create the secret before deploying:

```bash
aws secretsmanager create-secret --name my-github-pat --secret-string <PAT>
```

## Deployment

Deploy the stack with SAM and provide the secret name, AMI, subnet, security groups and
EC2 key pair used for the runner. You may also specify additional runner labels:

```bash
sam deploy \
  --parameter-overrides GitHubPATSecretName=my-github-pat \
  ExtraRunnerLabels="gpu" \
  ImageId=ami-0123456789abcdef0 \
  SubnetId=subnet-12345678 \
  SecurityGroupIds=sg-12345678 \
  KeyName=my-key
```

The `ExtraRunnerLabels` parameter is optional. When supplied, the labels are
added to the default runner labels. All other parameters are required and must
be specified for your environment.

## Local `samconfig.toml`

This repository ignores `samconfig.toml` so you can maintain environment-
specific settings locally. Copy `samconfig.toml.example` to `samconfig.toml`
and adjust the values for your AWS account. Then run SAM commands with the
desired configuration environment, for example:

```bash
sam build --config-env dev
sam deploy --config-env dev
```
