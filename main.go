package main //nolint: revive

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"text/template"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/google/go-github/v60/github"
)

//go:embed user-data.sh
var userData string

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

		// parse valid regions from env var
		validRegions := strings.Split(os.Getenv("VALID_REGIONS"), ",")
		region := "us-east-2"
		imageID := ""
		instanceType := types.InstanceTypeC7aLarge
		instanceTypes := instanceType.Values()

		for _, label := range event.GetWorkflowJob().Labels {
			// check AMI
			if strings.HasPrefix(label, "ami-") {
				imageID = label
			}
			// check region
			if slices.Contains(validRegions, label) {
				region = label
			}
			// check instance type
			for i := range instanceTypes {
				if label == string(instanceTypes[i]) {
					instanceType = instanceTypes[i]
				}
			}
		}

		cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(region))
		if err != nil {
			return events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}, err
		}

		svc := ec2.NewFromConfig(cfg)
		sm := secretsmanager.NewFromConfig(cfg)

		secretName := os.Getenv("GITHUB_PAT_SECRET_NAME")
		if secretName == "" {
			slog.Error("GITHUB_PAT_SECRET_NAME env var not set")

			return events.APIGatewayProxyResponse{
				StatusCode: http.StatusInternalServerError,
			}, errors.New("secret name missing")
		}

		secretOut, err := sm.GetSecretValue(context.TODO(), &secretsmanager.GetSecretValueInput{
			SecretId: aws.String(secretName),
		})
		if err != nil {
			//nolint:gosec
			slog.Error("failed to get secret", "secret", secretName, "error", err.Error())

			return events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}, err
		}

		pat := aws.ToString(secretOut.SecretString)

		extraLabels := os.Getenv("EXTRA_RUNNER_LABELS")
		if extraLabels != "" {
			extraLabels = "," + extraLabels
		}

		// discover subnets by tag
		const tagParts = 2

		filters := []types.Filter{}
		subnetTags := strings.Split(os.Getenv("SUBNET_TAGS"), ",")

		for _, tag := range subnetTags {
			parts := strings.SplitN(tag, "=", tagParts)
			if len(parts) != tagParts {
				continue
			}

			filters = append(filters, types.Filter{
				Name:   aws.String("tag:" + parts[0]),
				Values: []string{parts[1]},
			})
		}

		subnetResult, err := svc.DescribeSubnets(context.TODO(), &ec2.DescribeSubnetsInput{
			Filters: filters,
		})
		if err != nil {
			return events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}, err
		}

		if len(subnetResult.Subnets) == 0 {
			return events.APIGatewayProxyResponse{
					StatusCode: http.StatusInternalServerError,
				}, fmt.Errorf("no subnets found with tags %s in region %s",
					os.Getenv("SUBNET_TAGS"), region)
		}

		subnetID := *subnetResult.Subnets[0].SubnetId

		// discover security groups by tag
		filters = []types.Filter{}
		sgTags := strings.Split(os.Getenv("SECURITY_GROUP_TAGS"), ",")

		for _, tag := range sgTags {
			parts := strings.SplitN(tag, "=", tagParts)
			if len(parts) != tagParts {
				continue
			}

			filters = append(filters, types.Filter{
				Name:   aws.String("tag:" + parts[0]),
				Values: []string{parts[1]},
			})
		}

		sgResult, err := svc.DescribeSecurityGroups(context.TODO(), &ec2.DescribeSecurityGroupsInput{
			Filters: filters,
		})
		if err != nil {
			return events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}, err
		}

		securityGroups := []string{}
		for _, sg := range sgResult.SecurityGroups {
			securityGroups = append(securityGroups, *sg.GroupId)
		}

		instanceProfileArn := os.Getenv("INSTANCE_PROFILE_ARN")
		if instanceProfileArn == "" {
			slog.Error("INSTANCE_PROFILE_ARN env var not set")

			return events.APIGatewayProxyResponse{
				StatusCode: http.StatusInternalServerError,
			}, errors.New("instance profile arn missing")
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

		slog.Info("creating instance", "instanceType", instanceType)

		tpl, err := template.New("userdata").Parse(userData)
		if err != nil {
			return events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}, err
		}

		var buf bytes.Buffer

		err = tpl.Execute(&buf, map[string]string{"GitHubPAT": pat, "ExtraLabels": extraLabels})
		if err != nil {
			return events.APIGatewayProxyResponse{
				StatusCode: http.StatusInternalServerError,
			}, fmt.Errorf("failed to execute template: %w", err)
		}

		finalUserData := buf.String()

		output, err := svc.RunInstances(
			context.TODO(),
			&ec2.RunInstancesInput{
				MinCount:                          aws.Int32(1),
				MaxCount:                          aws.Int32(1),
				EbsOptimized:                      aws.Bool(true),
				ImageId:                           aws.String(imageID),
				InstanceInitiatedShutdownBehavior: types.ShutdownBehaviorTerminate,
				InstanceType:                      instanceType,
				IamInstanceProfile: &types.IamInstanceProfileSpecification{
					Arn: aws.String(instanceProfileArn),
				},
				NetworkInterfaces: []types.InstanceNetworkInterfaceSpecification{
					{
						AssociatePublicIpAddress: aws.Bool(true),
						SubnetId:                 aws.String(subnetID),
						DeleteOnTermination:      aws.Bool(true),
						DeviceIndex:              aws.Int32(0),
						Groups:                   securityGroups,
					},
				},
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
