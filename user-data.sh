#!/bin/bash
set -euo pipefail
set -x

# Get instance ID early for log stream naming
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
INSTANCE_ID=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id)

# CloudWatch logging setup
LOG_GROUP="/aws/ec2/github-runner"
LOG_STREAM="runner-${INSTANCE_ID}-$(date +%Y%m%d-%H%M%S)"
REGION="us-east-2"

# Configure AWS CLI default region
aws configure set default.region ${REGION}

# Function to log to CloudWatch
log_to_cloudwatch() {
    local level=$1
    local message=$2
    local timestamp=$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)
    
    # Also log to console
    echo "[${timestamp}] [${level}] ${message}"
    
    # Escape quotes and backslashes in message for JSON
    message=$(echo "$message" | sed 's/\\/\\\\/g' | sed 's/"/\\"/g')
    
    # Create properly formatted JSON for log event
    local log_event=$(printf '{"timestamp":%s,"message":"[%s] %s"}' "$(date +%s000)" "${level}" "${message}")
    
    # Send to CloudWatch
    if ! aws logs put-log-events \
        --log-group-name "${LOG_GROUP}" \
        --log-stream-name "${LOG_STREAM}" \
        --log-events "${log_event}" \
        --region "${REGION}" 2>&1; then
        echo "Failed to send log to CloudWatch"
    fi
}

# Create log group and stream
aws logs create-log-group --log-group-name "${LOG_GROUP}" --region "${REGION}" 2>/dev/null || true
aws logs create-log-stream --log-group-name "${LOG_GROUP}" --log-stream-name "${LOG_STREAM}" --region "${REGION}" 2>/dev/null || true

log_to_cloudwatch "INFO" "Starting GitHub runner setup"

START_TIME=$(date +%s)

# Set shutdown timer - this is the overall timeout
shutdown +60
log_to_cloudwatch "INFO" "Set 60-minute shutdown timer"

# Update apt sources if needed
sed -i 's/ap-southeast-3/us-east-2/g' /etc/apt/sources.list

# Add ubuntu user to docker group
usermod -aG docker ubuntu

# Use pre-extracted runner if available, otherwise extract from cache
if [ -d "/opt/actions-runner" ] && [ -f "/opt/actions-runner/run.sh" ]; then
    log_to_cloudwatch "INFO" "Using pre-extracted GitHub runner"
    cd /opt/actions-runner
else
    log_to_cloudwatch "INFO" "Pre-extracted runner not found, extracting from cache"

    # Find runner archive in cache
    RUNNER_ARCHIVE=$(ls /opt/runner-cache/actions-runner-linux-*.tar.gz 2>/dev/null | head -1)

    if [ -z "$RUNNER_ARCHIVE" ]; then
        log_to_cloudwatch "ERROR" "No runner archive found in /opt/runner-cache"
        shutdown now
        exit 1
    fi

    # Create directory and extract
    mkdir -p /opt/actions-runner
    cd /opt/actions-runner
    tar xzf "$RUNNER_ARCHIVE"
    chown -R ubuntu:ubuntu /opt/actions-runner
    log_to_cloudwatch "INFO" "Extracted runner from $RUNNER_ARCHIVE"
fi

# Get instance type (we already have instance ID from earlier)
INSTANCE_TYPE=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-type)

log_to_cloudwatch "INFO" "Instance: ${INSTANCE_ID}, Type: ${INSTANCE_TYPE}"

# JIT config is passed from Lambda - no need to call GitHub API or run config.sh
JIT_CONFIG="{{.JITConfig}}"

if [ -z "$JIT_CONFIG" ] || [ "$JIT_CONFIG" = "{{.JITConfig}}" ]; then
    log_to_cloudwatch "ERROR" "JIT config not provided"
    shutdown now
    exit 1
fi

log_to_cloudwatch "INFO" "JIT config received, skipping config.sh"

END_TIME=$(date +%s)
EXECUTION_TIME=$((END_TIME - START_TIME))
log_to_cloudwatch "INFO" "Setup completed in ${EXECUTION_TIME} seconds"

# Start the runner with JIT config (skips registration entirely)
log_to_cloudwatch "INFO" "Starting GitHub runner with JIT config"

# Create a temporary file to capture runner output
RUNNER_LOG=$(mktemp /tmp/runner-output.XXXXXX)

if sudo -u ubuntu ./run.sh --jitconfig "$JIT_CONFIG" 2>&1 | tee "${RUNNER_LOG}"; then
    log_to_cloudwatch "INFO" "Runner completed successfully"
else
    EXIT_CODE=$?
    log_to_cloudwatch "ERROR" "Runner exited with error code: ${EXIT_CODE}"
    
    # Send the last 50 lines of runner output to CloudWatch
    RUNNER_ERROR=$(tail -n 50 "${RUNNER_LOG}" | head -c 4096)
    log_to_cloudwatch "ERROR" "Runner output: ${RUNNER_ERROR}"
fi

# Clean up
rm -f "${RUNNER_LOG}"

# Cancel the 60-minute shutdown timer since we're shutting down normally
shutdown -c 2>/dev/null || true

# Shutdown the instance
log_to_cloudwatch "INFO" "Shutting down instance after runner completion"
shutdown now