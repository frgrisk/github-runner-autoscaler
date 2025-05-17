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

Deploy the stack with SAM and provide the secret name and any additional runner
labels as parameters:

```bash
sam deploy \
  --parameter-overrides GitHubPATSecretName=my-github-pat \
  --parameter-overrides ExtraRunnerLabels="gpu"
```

The `ExtraRunnerLabels` parameter is optional. When supplied, the labels are
added to the default runner labels.
