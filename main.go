package main //nolint: revive

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"text/template"
	"time"

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

// LaunchConfig holds common EC2 launch configuration.
type LaunchConfig struct {
	ImageID            string
	SubnetID           string
	SecurityGroups     []string
	KeyName            string
	InstanceProfileArn string
}

// parseWarmPoolConfig parses the WARM_POOL_CONFIG environment variable.
// Returns a map of instance type to target pool size.
func parseWarmPoolConfig() map[string]int {
	configStr := os.Getenv("WARM_POOL_CONFIG")
	if configStr == "" || configStr == "{}" {
		return nil
	}

	var poolConfig map[string]int
	if err := json.Unmarshal([]byte(configStr), &poolConfig); err != nil {
		slog.Error("failed to parse WARM_POOL_CONFIG", "error", err.Error(), "config", configStr)
		return nil
	}

	return poolConfig
}

// findAvailableWarmInstance searches for a stopped warm pool instance of the requested type.
func findAvailableWarmInstance(ctx context.Context, svc *ec2.Client, instanceType types.InstanceType) (*string, error) {
	output, err := svc.DescribeInstances(ctx, &ec2.DescribeInstancesInput{
		Filters: []types.Filter{
			{
				Name:   aws.String("tag:WarmPool"),
				Values: []string{"true"},
			},
			{
				Name:   aws.String("tag:WarmPoolStatus"),
				Values: []string{"available"},
			},
			{
				Name:   aws.String("tag:WarmPoolInstanceType"),
				Values: []string{string(instanceType)},
			},
			{
				Name:   aws.String("instance-state-name"),
				Values: []string{"stopped"},
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to describe instances: %w", err)
	}

	for _, reservation := range output.Reservations {
		for _, instance := range reservation.Instances {
			return instance.InstanceId, nil
		}
	}

	return nil, nil // No available instance found
}

// startWarmInstance activates a stopped warm pool instance for a job.
// It sets the activation tag, updates user-data, changes shutdown behavior to TERMINATE, and starts the instance.
func startWarmInstance(ctx context.Context, svc *ec2.Client, instanceID string, jobEventID int64, finalUserData string) error {
	// Update tags to mark as activated and in-use
	_, err := svc.CreateTags(ctx, &ec2.CreateTagsInput{
		Resources: []string{instanceID},
		Tags: []types.Tag{
			{Key: aws.String("WarmPoolStatus"), Value: aws.String("in-use")},
			{Key: aws.String("WarmPoolActivated"), Value: aws.String("true")},
			{Key: aws.String("GitHub Workflow Job Event ID"), Value: aws.String(strconv.FormatInt(jobEventID, 10))},
			{Key: aws.String("Name"), Value: aws.String("GitHub Workflow Ephemeral Runner")},
		},
	})
	if err != nil {
		return fmt.Errorf("failed to update tags: %w", err)
	}

	// Change shutdown behavior to TERMINATE so instance terminates after job
	_, err = svc.ModifyInstanceAttribute(ctx, &ec2.ModifyInstanceAttributeInput{
		InstanceId: aws.String(instanceID),
		InstanceInitiatedShutdownBehavior: &types.AttributeValue{
			Value: aws.String("terminate"),
		},
	})
	if err != nil {
		return fmt.Errorf("failed to update shutdown behavior: %w", err)
	}

	// Update user data with the full setup script wrapped in multipart format
	// so it runs on every boot (including this activation)
	wrappedUserData := wrapInMultipart(finalUserData)
	encodedUserData := base64.StdEncoding.EncodeToString([]byte(wrappedUserData))
	_, err = svc.ModifyInstanceAttribute(ctx, &ec2.ModifyInstanceAttributeInput{
		InstanceId: aws.String(instanceID),
		UserData:   &types.BlobAttributeValue{Value: []byte(encodedUserData)},
	})
	if err != nil {
		return fmt.Errorf("failed to update user data: %w", err)
	}

	// Start the instance
	startOutput, err := svc.StartInstances(ctx, &ec2.StartInstancesInput{
		InstanceIds: []string{instanceID},
	})
	if err != nil {
		return fmt.Errorf("failed to start instance: %w", err)
	}

	// Verify the instance was actually stopped before we started it
	for _, change := range startOutput.StartingInstances {
		if *change.InstanceId == instanceID {
			if change.PreviousState.Name != types.InstanceStateNameStopped {
				return fmt.Errorf("instance %s was not stopped (was %s)", instanceID, change.PreviousState.Name)
			}
		}
	}

	return nil
}

// countWarmPoolInstances counts available instances in the warm pool for a given type.
func countWarmPoolInstances(ctx context.Context, svc *ec2.Client, instanceType types.InstanceType) (int, error) {
	output, err := svc.DescribeInstances(ctx, &ec2.DescribeInstancesInput{
		Filters: []types.Filter{
			{
				Name:   aws.String("tag:WarmPool"),
				Values: []string{"true"},
			},
			{
				Name:   aws.String("tag:WarmPoolStatus"),
				Values: []string{"available"},
			},
			{
				Name:   aws.String("tag:WarmPoolInstanceType"),
				Values: []string{string(instanceType)},
			},
			{
				Name:   aws.String("instance-state-name"),
				Values: []string{"stopped", "stopping"},
			},
		},
	})
	if err != nil {
		return 0, fmt.Errorf("failed to describe instances: %w", err)
	}

	count := 0
	for _, reservation := range output.Reservations {
		count += len(reservation.Instances)
	}

	return count, nil
}

// warmPoolInitUserData is a minimal script that stops the instance on first boot.
// Uses multipart MIME format with cloud-config to run scripts on every boot.
const warmPoolInitUserData = `Content-Type: multipart/mixed; boundary="//"
MIME-Version: 1.0

--//
Content-Type: text/cloud-config; charset="us-ascii"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit
Content-Disposition: attachment; filename="cloud-config.txt"

#cloud-config
cloud_final_modules:
- [scripts-user, always]

--//
Content-Type: text/x-shellscript; charset="us-ascii"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit
Content-Disposition: attachment; filename="userdata.txt"

#!/bin/bash
# Warm pool init: just stop the instance after first boot
# When activated, user-data will be replaced with the real setup script
echo "Warm pool instance initializing, stopping to enter pool..."
shutdown -h now
--//--
`

// wrapInMultipart wraps a shell script in multipart MIME format that runs on every boot.
func wrapInMultipart(script string) string {
	return fmt.Sprintf(`Content-Type: multipart/mixed; boundary="//"
MIME-Version: 1.0

--//
Content-Type: text/cloud-config; charset="us-ascii"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit
Content-Disposition: attachment; filename="cloud-config.txt"

#cloud-config
cloud_final_modules:
- [scripts-user, always]

--//
Content-Type: text/x-shellscript; charset="us-ascii"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit
Content-Disposition: attachment; filename="userdata.txt"

%s
--//--
`, script)
}

// launchWarmPoolInstance launches a new instance destined for the warm pool.
// Instances will stop after first boot and terminate after being used for a job.
func launchWarmPoolInstance(ctx context.Context, svc *ec2.Client, instanceType types.InstanceType, launchConfig LaunchConfig) (*string, error) {
	tags := []types.Tag{
		{Key: aws.String("WarmPool"), Value: aws.String("true")},
		{Key: aws.String("WarmPoolStatus"), Value: aws.String("available")},
		{Key: aws.String("WarmPoolActivated"), Value: aws.String("false")},
		{Key: aws.String("WarmPoolInstanceType"), Value: aws.String(string(instanceType))},
		{Key: aws.String("WarmPoolCreatedAt"), Value: aws.String(time.Now().UTC().Format(time.RFC3339))},
		{Key: aws.String("Name"), Value: aws.String(fmt.Sprintf("GitHub Runner Warm Pool - %s", instanceType))},
	}

	output, err := svc.RunInstances(ctx, &ec2.RunInstancesInput{
		MinCount:                          aws.Int32(1),
		MaxCount:                          aws.Int32(1),
		EbsOptimized:                      aws.Bool(true),
		ImageId:                           aws.String(launchConfig.ImageID),
		InstanceInitiatedShutdownBehavior: types.ShutdownBehaviorStop, // STOP on first boot to enter warm pool
		InstanceType:                      instanceType,
		IamInstanceProfile: &types.IamInstanceProfileSpecification{
			Arn: aws.String(launchConfig.InstanceProfileArn),
		},
		NetworkInterfaces: []types.InstanceNetworkInterfaceSpecification{
			{
				AssociatePublicIpAddress: aws.Bool(true),
				SubnetId:                 aws.String(launchConfig.SubnetID),
				DeleteOnTermination:      aws.Bool(true),
				DeviceIndex:              aws.Int32(0),
				Groups:                   launchConfig.SecurityGroups,
			},
		},
		KeyName:    aws.String(launchConfig.KeyName),
		Monitoring: &types.RunInstancesMonitoringEnabled{Enabled: aws.Bool(true)},
		TagSpecifications: []types.TagSpecification{
			{ResourceType: types.ResourceTypeInstance, Tags: tags},
			{ResourceType: types.ResourceTypeVolume, Tags: tags},
		},
		UserData: aws.String(base64.StdEncoding.EncodeToString([]byte(warmPoolInitUserData))),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to launch warm pool instance: %w", err)
	}

	if len(output.Instances) == 0 {
		return nil, errors.New("no instance created")
	}

	return output.Instances[0].InstanceId, nil
}

// launchFreshInstance launches a new instance that terminates after use (current behavior).
func launchFreshInstance(ctx context.Context, svc *ec2.Client, instanceType types.InstanceType, launchConfig LaunchConfig, finalUserData string, jobEventID int64) (*string, error) {
	tags := []types.Tag{
		{
			Key:   aws.String("GitHub Workflow Job Event ID"),
			Value: aws.String(strconv.FormatInt(jobEventID, 10)),
		},
		{
			Key:   aws.String("Name"),
			Value: aws.String("GitHub Workflow Ephemeral Runner"),
		},
	}

	output, err := svc.RunInstances(ctx, &ec2.RunInstancesInput{
		MinCount:                          aws.Int32(1),
		MaxCount:                          aws.Int32(1),
		EbsOptimized:                      aws.Bool(true),
		ImageId:                           aws.String(launchConfig.ImageID),
		InstanceInitiatedShutdownBehavior: types.ShutdownBehaviorTerminate,
		InstanceType:                      instanceType,
		IamInstanceProfile: &types.IamInstanceProfileSpecification{
			Arn: aws.String(launchConfig.InstanceProfileArn),
		},
		NetworkInterfaces: []types.InstanceNetworkInterfaceSpecification{
			{
				AssociatePublicIpAddress: aws.Bool(true),
				SubnetId:                 aws.String(launchConfig.SubnetID),
				DeleteOnTermination:      aws.Bool(true),
				DeviceIndex:              aws.Int32(0),
				Groups:                   launchConfig.SecurityGroups,
			},
		},
		KeyName:    aws.String(launchConfig.KeyName),
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
		UserData: aws.String(base64.StdEncoding.EncodeToString([]byte(finalUserData))),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to launch instance: %w", err)
	}

	if len(output.Instances) == 0 {
		return nil, errors.New("no instance created")
	}

	return output.Instances[0].InstanceId, nil
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

		ctx := context.TODO()

		cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion("us-east-2"))
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

		secretOut, err := sm.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{SecretId: aws.String(secretName)})
		if err != nil {
			slog.Error("failed to get secret", "secret", secretName, "error", err.Error())

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

		instanceProfileArn := os.Getenv("INSTANCE_PROFILE_ARN")
		if instanceProfileArn == "" {
			slog.Error("INSTANCE_PROFILE_ARN env var not set")

			return events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}, errors.New("instance profile arn missing")
		}

		imageID := os.Getenv("IMAGE_ID")
		if imageID == "" {
			slog.Error("IMAGE_ID env var not set")

			return events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}, errors.New("image id missing")
		}

		launchConfig := LaunchConfig{
			ImageID:            imageID,
			SubnetID:           subnetID,
			SecurityGroups:     securityGroups,
			KeyName:            keyName,
			InstanceProfileArn: instanceProfileArn,
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

		slog.Info("processing job", "instanceType", instanceType, "jobID", event.GetWorkflowJob().GetID())

		tpl, err := template.New("userdata").Parse(userData)
		if err != nil {
			return events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}, err
		}

		var buf bytes.Buffer
		if err := tpl.Execute(&buf, map[string]string{"GitHubPAT": pat, "ExtraLabels": extraLabels}); err != nil {
			return events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}, err
		}

		finalUserData := buf.String()
		jobEventID := event.GetWorkflowJob().GetID()

		// Parse warm pool configuration
		poolConfig := parseWarmPoolConfig()
		targetSize := 0
		if poolConfig != nil {
			targetSize = poolConfig[string(instanceType)]
		}

		var instanceID *string

		// Try warm pool if configured for this instance type
		if targetSize > 0 {
			slog.Info("checking warm pool", "instanceType", instanceType, "targetSize", targetSize)

			warmInstanceID, err := findAvailableWarmInstance(ctx, svc, instanceType)
			if err != nil {
				slog.Warn("failed to query warm pool", "error", err.Error())
				// Fall through to fresh launch
			} else if warmInstanceID != nil {
				slog.Info("found warm pool instance", "instanceID", *warmInstanceID)

				err = startWarmInstance(ctx, svc, *warmInstanceID, jobEventID, finalUserData)
				if err != nil {
					slog.Error("failed to start warm instance", "instanceID", *warmInstanceID, "error", err.Error())
					// Mark instance for cleanup and fall through to fresh launch
					_, _ = svc.CreateTags(ctx, &ec2.CreateTagsInput{
						Resources: []string{*warmInstanceID},
						Tags: []types.Tag{
							{Key: aws.String("WarmPoolStatus"), Value: aws.String("failed")},
						},
					})
				} else {
					instanceID = warmInstanceID
					slog.Info("started warm pool instance", "instanceID", *instanceID)
				}
			} else {
				slog.Info("no warm pool instance available", "instanceType", instanceType)
			}
		}

		// Fallback: launch fresh instance if no warm pool instance was used
		if instanceID == nil {
			slog.Info("launching fresh instance", "instanceType", instanceType)

			if targetSize > 0 {
				// Warm pool is configured but no instance available - launch fresh instance that terminates
				// (Don't create a warm pool instance that will stop - we need it now)
				instanceID, err = launchFreshInstance(ctx, svc, instanceType, launchConfig, finalUserData, jobEventID)
				if err != nil {
					slog.Error("failed to launch fresh instance", "error", err.Error())
					return events.APIGatewayProxyResponse{
						Body:       err.Error(),
						StatusCode: http.StatusInternalServerError,
					}, err
				}
			} else {
				// No warm pool configured - launch regular instance that terminates
				instanceID, err = launchFreshInstance(ctx, svc, instanceType, launchConfig, finalUserData, jobEventID)
				if err != nil {
					slog.Error("failed to launch fresh instance", "error", err.Error())
					return events.APIGatewayProxyResponse{
						Body:       err.Error(),
						StatusCode: http.StatusInternalServerError,
					}, err
				}
			}

			slog.Info("instance launched", "instanceID", *instanceID)
		}

		// Replenish warm pool if we used a warm instance (or if pool is under target)
		if targetSize > 0 {
			currentCount, err := countWarmPoolInstances(ctx, svc, instanceType)
			if err != nil {
				slog.Warn("failed to count warm pool", "error", err.Error())
			} else if currentCount < targetSize {
				slog.Info("replenishing warm pool", "instanceType", instanceType, "current", currentCount, "target", targetSize)

				newID, err := launchWarmPoolInstance(ctx, svc, instanceType, launchConfig)
				if err != nil {
					slog.Warn("failed to launch warm pool replacement", "error", err.Error())
				} else {
					slog.Info("launched warm pool replacement", "instanceID", *newID)
				}
			}
		}

		return events.APIGatewayProxyResponse{
			Body:       *instanceID,
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
