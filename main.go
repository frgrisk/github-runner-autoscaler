package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/google/go-github/v60/github"
)

type ec2RunInstancesAPI interface {
	RunInstances(ctx context.Context, params *ec2.RunInstancesInput, optFns ...func(*ec2.Options)) (*ec2.RunInstancesOutput, error)
}

var newEC2Client = func(cfg aws.Config) ec2RunInstancesAPI {
	return ec2.NewFromConfig(cfg)
}

var loadAWSConfig = func(ctx context.Context, optFns ...func(*config.LoadOptions) error) (aws.Config, error) {
	return config.LoadDefaultConfig(ctx, optFns...)
}

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
		return events.APIGatewayProxyResponse{StatusCode: 200}, nil
	}
	body := request.Body
	if request.IsBase64Encoded {
		decoded, err := base64.StdEncoding.DecodeString(request.Body)
		if err != nil {
			slog.Error("failed to decode body", "error", err.Error())
			return events.APIGatewayProxyResponse{StatusCode: 400}, nil
		}
		body = string(decoded)
	}
	event, err := github.ParseWebHook(githubEventHeader, []byte(body))
	if err != nil {
		slog.Error("error parsing webhook", "error", err.Error())
		return events.APIGatewayProxyResponse{StatusCode: 200}, nil
	}
	switch event := event.(type) {
	case *github.WorkflowJobEvent:
		if event.GetAction() != "queued" {
			slog.Info("not a queued job event")
			return events.APIGatewayProxyResponse{StatusCode: 200}, nil
		}
		cfg, err := loadAWSConfig(context.TODO(), config.WithRegion("us-east-2"))
		if err != nil {
			return events.APIGatewayProxyResponse{StatusCode: 500}, err
		}
		svc := newEC2Client(cfg)
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
			return events.APIGatewayProxyResponse{StatusCode: 200}, nil
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
		output, err := svc.RunInstances(
			context.TODO(),
			&ec2.RunInstancesInput{
				MinCount:                          aws.Int32(1),
				MaxCount:                          aws.Int32(1),
				EbsOptimized:                      aws.Bool(true),
				ImageId:                           aws.String("ami-0c0c88099397fccb4"),
				InstanceInitiatedShutdownBehavior: types.ShutdownBehaviorTerminate,
				InstanceType:                      instanceType,
				SubnetId:                          aws.String("subnet-0c7485057fba6c4f6"),
				SecurityGroupIds:                  []string{"sg-0e61236689c685844"},
				KeyName:                           aws.String("terraform-20220125192645402400000001"),
				Monitoring:                        &types.RunInstancesMonitoringEnabled{Enabled: aws.Bool(true)},
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
				UserData: aws.String(base64.StdEncoding.EncodeToString([]byte(userData))),
			},
		)
		if err != nil {
			slog.Error(err.Error())
			return events.APIGatewayProxyResponse{
				Body:       err.Error(),
				StatusCode: 500,
			}, err
		}
		if len(output.Instances) == 0 {
			slog.Info("no instance created")
			return events.APIGatewayProxyResponse{
				Body:       "no instance created",
				StatusCode: 500,
			}, nil
		}
		slog.Info("instance created", "instanceID", output.Instances[0].InstanceId)
		return events.APIGatewayProxyResponse{
			Body:       *output.Instances[0].InstanceId,
			StatusCode: 200,
		}, nil

	default:
		fmt.Printf("unknown event type %T\n", event)
	}

	return events.APIGatewayProxyResponse{
		Body:       "Hello World",
		StatusCode: 200,
	}, nil
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
sudo -u ubuntu ./config.sh --url https://github.com/frgrisk --token $GITHUB_TOKEN --disableupdate --ephemeral --labels $INSTANCE_TYPE,ephemeral,X64 --unattended
END_TIME=$(date +%s)
EXECUTION_TIME=$((END_TIME - START_TIME))
echo "Script execution time: $EXECUTION_TIME seconds" | tee -a /var/log/setup-time.log
sudo -u ubuntu ./run.sh
shutdown now
`
