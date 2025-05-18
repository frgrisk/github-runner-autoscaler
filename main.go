package main //nolint: revive

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/google/go-github/v60/github"
)

func handler(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	var githubEventHeader string

	for k, v := range request.MultiValueHeaders {
		if strings.EqualFold(k, github.EventTypeHeader) {
			if len(v) > 0 {
				githubEventHeader = v[0]
			}

			break
		}
	}

	if githubEventHeader == "" {
		slog.Info("no github event header")

		return events.APIGatewayProxyResponse{StatusCode: http.StatusOK}, nil
	}

	event, err := github.ParseWebHook(githubEventHeader, []byte(request.Body))
	if err != nil {
		slog.Error("error parsing webhook", "error", err.Error())

		return events.APIGatewayProxyResponse{StatusCode: http.StatusOK}, nil
	}

	switch event := event.(type) {
	case *github.WorkflowJobEvent:
		if event.GetAction() != "queued" {
			slog.Info("not a queued job event")

			return events.APIGatewayProxyResponse{StatusCode: http.StatusOK}, nil
		}

		cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion("us-east-2"))
		if err != nil {
			return events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}, err
		}

		svc := ec2.NewFromConfig(cfg)
		sm := secretsmanager.NewFromConfig(cfg)

		secretName := os.Getenv("GITHUB_PAT_SECRET_NAME")
		if secretName == "" {
			slog.Error("GITHUB_PAT_SECRET_NAME env var not set")

			return events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}, errors.New("secret name missing")
		}

		secretOut, err := sm.GetSecretValue(context.TODO(), &secretsmanager.GetSecretValueInput{SecretId: aws.String(secretName)})
		if err != nil {
			slog.Error("failed to get secret", "error", err.Error())

			return events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}, err
		}

		pat := aws.ToString(secretOut.SecretString)

		extraLabels := os.Getenv("EXTRA_RUNNER_LABELS")
		if extraLabels != "" {
			extraLabels = "," + extraLabels
		}

		subnetID := os.Getenv("SUBNET_ID")
		if subnetID == "" {
			slog.Error("SUBNET_ID env var not set")

			return events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}, errors.New("subnet id missing")
		}

		sgIDs := os.Getenv("SECURITY_GROUP_IDS")
		if sgIDs == "" {
			slog.Error("SECURITY_GROUP_IDS env var not set")

			return events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}, errors.New("security groups missing")
		}
		securityGroups := strings.Split(sgIDs, ",")

		keyName := os.Getenv("KEY_NAME")
		if keyName == "" {
			slog.Error("KEY_NAME env var not set")

			return events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}, errors.New("key name missing")
		}

		imageID := os.Getenv("IMAGE_ID")
		if imageID == "" {
			slog.Error("IMAGE_ID env var not set")

			return events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}, errors.New("image id missing")
		}

		tags := []types.Tag{
			{
				Key:   aws.String("GitHub Workflow Job Event ID"),
				Value: aws.String(strconv.Itoa(int(event.GetWorkflowJob().GetID()))),
			},
			{
				Key:   aws.String("Name"),
				Value: aws.String("GitHub Workflow Ephemeral Runner"),
			},
		}

		ephemeral := slices.Contains(event.GetWorkflowJob().Labels, "ephemeral")
		if !ephemeral {
			slog.Info("not ephemeral")

			return events.APIGatewayProxyResponse{StatusCode: http.StatusOK}, nil
		}

		instanceType := types.InstanceTypeC7aLarge

		instanceTypes := instanceType.Values()
		for _, label := range event.GetWorkflowJob().Labels {
			for i := range instanceTypes {
				if label == string(instanceTypes[i]) {
					instanceType = instanceTypes[i]

					break
				}
			}
		}

		slog.Info("creating instance", "instanceType", instanceType)

		finalUserData := strings.ReplaceAll(userData, "<GITHUB_PAT>", pat)
		finalUserData = strings.ReplaceAll(finalUserData, "<EXTRA_LABELS>", extraLabels)

		output, err := svc.RunInstances(
			context.TODO(),
			&ec2.RunInstancesInput{
				MinCount:                          aws.Int32(1),
				MaxCount:                          aws.Int32(1),
				EbsOptimized:                      aws.Bool(true),
				ImageId:                           aws.String(imageID),
				InstanceInitiatedShutdownBehavior: types.ShutdownBehaviorTerminate,
				InstanceType:                      instanceType,
				NetworkInterfaces: []types.InstanceNetworkInterfaceSpecification{
					{
						AssociatePublicIpAddress: aws.Bool(true),
						SubnetId:                 aws.String(subnetID),
						DeleteOnTermination:      aws.Bool(true),
						DeviceIndex:              aws.Int32(0),
						Groups:                   securityGroups,
					},
				},
				KeyName:    aws.String(keyName),
				Monitoring: &types.RunInstancesMonitoringEnabled{Enabled: aws.Bool(true)},
				TagSpecifications: []types.TagSpecification{
					{
						ResourceType: types.ResourceTypeInstance,
						Tags:         tags,
					},
					{
						ResourceType: types.ResourceTypeVolume,
						Tags:         tags,
					},
				},
				// base64 encode user data
				UserData: aws.String(base64.StdEncoding.EncodeToString([]byte(finalUserData))),
			},
		)
		if err != nil {
			slog.Error(err.Error())

			return events.APIGatewayProxyResponse{
				Body:       err.Error(),
				StatusCode: http.StatusInternalServerError,
			}, err
		}

		if len(output.Instances) == 0 {
			slog.Error("no instance created")

			return events.APIGatewayProxyResponse{
				Body:       "no instance created",
				StatusCode: http.StatusInternalServerError,
			}, nil
		}

		slog.Info("instance created", "instanceID", output.Instances[0].InstanceId)

		return events.APIGatewayProxyResponse{
			Body:       *output.Instances[0].InstanceId,
			StatusCode: http.StatusOK,
		}, nil

	default:
		err = fmt.Errorf("unknown event type %T", event)
		slog.Error(err.Error())

		return events.APIGatewayProxyResponse{
			Body:       err.Error(),
			StatusCode: http.StatusInternalServerError,
		}, err
	}
}

func main() {
	lambda.Start(handler)
}

var userData = `#!/bin/bash
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
  -H "Authorization: Bearer <GITHUB_PAT>" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  https://api.github.com/orgs/frgrisk/actions/runners/registration-token | jq -r .token)
sudo -u ubuntu ./config.sh --url https://github.com/frgrisk --token $GITHUB_TOKEN --disableupdate --ephemeral --labels $INSTANCE_TYPE,ephemeral,X64<EXTRA_LABELS> --unattended
END_TIME=$(date +%s)
EXECUTION_TIME=$((END_TIME - START_TIME))
echo "Script execution time: $EXECUTION_TIME seconds" | tee -a /var/log/setup-time.log
sudo -u ubuntu ./run.sh
shutdown now
`
