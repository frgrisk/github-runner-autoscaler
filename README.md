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

### Rotating the PAT

If your PAT expires or is revoked, update the secret in Secrets Manager:

```bash
aws secretsmanager put-secret-value --secret-id my-github-pat --secret-string <NEW_PAT>
```

No redeployment needed. The Lambda fetches the secret at runtime.

## Deployment

Deploy the stack with SAM and provide the secret name, AMI, subnet, security groups and
EC2 key pair used for the runner. You may also specify additional runner labels:

```bash
sam deploy \
  --parameter-overrides GitHubPATSecretName=my-github-pat \
  ExtraRunnerLabels="gpu" \
  RunnerConfiguration='{\"us-east-2\":{\"ami\":\"0c0c88099397fccb4\",\"subnet\":[\"subnet-0123456789def\"],\"sg\":[\"sg-0123456789def\"],\"key\":\"terraform-2025051801\"},\"ap-southeast-5\":{\"ami\":\"0c0c88099397fccb4\",\"subnet\":[\"subnet-0123456789def\"],\"sg\":[\"sg-0123456789def\"],\"key\":\"terraform-2025051801\"}}'
```

The `ExtraRunnerLabels` parameter is optional. When supplied, the labels are
added to the default runner labels. All other parameters are required and must
be specified for your environment.

## Reconciling stuck jobs

GitHub does not retry a webhook delivery that fails or times out, so a job whose
`queued` delivery is lost, whose launch fails, or whose instance dies before
registering waits for a runner that never comes. Set `ReconcileRepositories` to
a comma separated `owner/repo` list to deploy a second function that catches
these jobs:

```bash
sam deploy --config-env <env> --parameter-overrides ReconcileRepositories=your-org/your-repo ...
```

Every two minutes it lists the queued jobs in those repositories. For each job
with the `ephemeral` label that has waited five minutes, it checks the EC2
instances tagged with the job's ID and launches another runner if none started
in the last five minutes. It stops after three runners per job and fails the
invocation instead, so the function's `Errors` metric shows jobs it could not
unstick. It skips jobs whose labels a runner from this stack would not have.

The reconciler reads workflow runs and jobs with the same PAT, which therefore
also needs read access to Actions in those repositories (`repo` scope on a
classic token). To reconcile immediately rather than wait for the schedule,
invoke the function named by the `RunnerReconcilerFunction` stack output:

```bash
aws lambda invoke --function-name <RunnerReconcilerFunction ARN> /dev/stdout
```

Leaving the parameter empty, the default, deploys no reconciler.

## Local `samconfig.toml`

This repository ignores `samconfig.toml` and `samconfig.yaml` so you can
maintain environment-specific settings locally. Copy `samconfig.example.yaml`
to `samconfig.yaml` and adjust the values for your AWS account. Then run SAM
commands with the desired configuration environment, for example:

```bash
sam build --config-env dev
sam deploy --config-env dev
```
