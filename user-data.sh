#!/bin/bash
set -x
START_TIME=$(date +%s)
shutdown +60
sed -i 's/ap-southeast-3/us-east-2/g' /etc/apt/sources.list
usermod -aG docker ubuntu
cd /opt
mkdir actions-runner
chown -R ubuntu:ubuntu actions-runner
cd actions-runner
sudo -u ubuntu tar xzf ../runner-cache/actions-runner-linux-* -C .
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
INSTANCE_TYPE=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-type)
GITHUB_TOKEN=$(curl -L \
  -X POST \
  -H "Accept: application/vnd.github+json" \
  -H "Authorization: Bearer {{.GitHubPAT}}" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  https://api.github.com/orgs/frgrisk/actions/runners/registration-token | jq -r .token)
sudo -u ubuntu ./config.sh --url https://github.com/frgrisk --token $GITHUB_TOKEN --disableupdate --ephemeral --labels $INSTANCE_TYPE,ephemeral,X64{{.ExtraLabels}} --unattended
END_TIME=$(date +%s)
EXECUTION_TIME=$((END_TIME - START_TIME))
echo "Script execution time: $EXECUTION_TIME seconds" | tee -a /var/log/setup-time.log
sudo -u ubuntu ./run.sh
shutdown now
