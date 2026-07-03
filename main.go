package main //nolint: revive

import (
	"bytes"
	"cmp"
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
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
	"github.com/aws/smithy-go"
	"github.com/google/go-github/v60/github"
)

//go:embed user-data.sh
var userData string

type RunnerConfiguration struct {
	ImageID        string   `json:"ami"`
	SubnetID       []string `json:"subnet"`
	SecurityGroups []string `json:"sg"`
	KeyName        string   `json:"key"`
}

// retryableLaunchErrors are EC2 error codes for which launching the runner in
// the next configured subnet (potentially a different AZ) or the next candidate
// instance type may succeed.
var retryableLaunchErrors = []string{
	"InsufficientFreeAddressesInSubnet",
	"InsufficientInstanceCapacity",
	"InvalidSubnetID.NotFound",
	"Unsupported",
}

// throttlingErrorCodes are EC2 error codes indicating the account is being rate
// limited. Trying a different subnet does not help because the limit is
// account-wide, so the launch loop backs off before trying again.
var throttlingErrorCodes = []string{
	"RequestLimitExceeded",
	"Throttling",
	"ThrottlingException",
	"RequestThrottled",
}

const (
	// baseLaunchBackoff is the initial wait before retrying a full pass over
	// all subnets after they have all failed with a retryable/throttling error.
	baseLaunchBackoff = 1 * time.Second
	// maxLaunchBackoff caps the exponential backoff between retry passes. The
	// Lambda is bounded by a 29s API Gateway timeout, so the cap is deliberately
	// small: a large cap would spend most of the window asleep and get in only
	// one or two attempts. At 1s/2s/4s (then capped) with jitter, the window
	// fits roughly five or six full subnet passes before ctx is cancelled.
	maxLaunchBackoff = 4 * time.Second
)

// launchBackoff returns the wait before the given retry pass (0-indexed) using
// exponential backoff with equal jitter. The jitter spreads retries out so many
// concurrently throttled Lambda invocations do not all retry at the same instant
// and re-trigger the rate limit.
func launchBackoff(attempt int) time.Duration {
	backoff := maxLaunchBackoff
	if attempt < 5 {
		backoff = baseLaunchBackoff << attempt
		if backoff > maxLaunchBackoff {
			backoff = maxLaunchBackoff
		}
	}

	half := backoff / 2

	return half + time.Duration(rand.Int64N(int64(half)+1))
}

// launchInstance repeatedly attempts to launch a runner across the configured
// instance types and subnets. It tries each instance type in turn, and for each
// type sweeps every subnet; capacity/subnet errors move on to the next subnet
// (then the next type), so a type that is out of capacity in every AZ falls
// through to the next candidate. Account-wide throttling stops the current pass
// early. After a full pass with no success it backs off (with jitter) and tries
// again, looping until an instance is launched, a non-retryable error occurs, or
// ctx is cancelled (which happens when the Lambda invocation nears its timeout).
func launchInstance(
	ctx context.Context,
	svc *ec2.Client,
	runInput *ec2.RunInstancesInput,
	instanceTypes []types.InstanceType,
	subnets []string,
) (string, error) {
	var lastErr error

	for attempt := 0; ; attempt++ {
	typeLoop:
		for _, instanceType := range instanceTypes {
			runInput.InstanceType = instanceType

			for _, subnet := range subnets {
				runInput.NetworkInterfaces[0].SubnetId = aws.String(subnet)

				output, err := svc.RunInstances(ctx, runInput)
				if err != nil {
					apiErr, ok := errors.AsType[smithy.APIError](err)

					switch {
					case ok && slices.Contains(throttlingErrorCodes, apiErr.ErrorCode()):
						slog.Warn(
							"throttled launching instance, backing off before retry",
							"instanceType", instanceType,
							"subnet", subnet,
							"reason", apiErr.ErrorCode(),
						)

						lastErr = err

						// Account-wide limit: stop trying other subnets and
						// instance types this pass and go straight to backoff.
						break typeLoop
					case ok && slices.Contains(retryableLaunchErrors, apiErr.ErrorCode()):
						slog.Warn(
							"retrying in next subnet",
							"instanceType", instanceType,
							"subnet", subnet,
							"reason", apiErr.ErrorCode(),
						)

						lastErr = err

						continue
					default:
						slog.Error("failed to run instances", "error", err.Error())

						return "", err
					}
				}

				if len(output.Instances) == 0 || output.Instances[0].InstanceId == nil {
					slog.Warn(
						"no instance created in subnet, trying next",
						"instanceType", instanceType,
						"subnet", subnet,
					)

					lastErr = errors.New("run instances returned no instance id")

					continue
				}

				return aws.ToString(output.Instances[0].InstanceId), nil
			}

			slog.Warn(
				"all subnets failed for instance type, trying next type",
				"instanceType", instanceType,
			)
		}

		delay := launchBackoff(attempt)
		slog.Warn(
			"all instance types and subnets failed, backing off before next retry pass",
			"attempt", attempt+1,
			"delay", delay.String(),
		)

		timer := time.NewTimer(delay)

		select {
		case <-ctx.Done():
			timer.Stop()

			if lastErr == nil {
				lastErr = ctx.Err()
			}

			return "", fmt.Errorf("timed out before launching instance: %w", lastErr)
		case <-timer.C:
		}
	}
}

func handler(
	ctx context.Context,
	request events.APIGatewayProxyRequest,
) (events.APIGatewayProxyResponse, error) {
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

		runnerCfg := os.Getenv("RUNNER_CONFIGURATION")
		if runnerCfg == "" {
			slog.Error("RUNNER_CONFIGURATION env var not set")

			return events.APIGatewayProxyResponse{
				StatusCode: http.StatusInternalServerError,
			}, errors.New("runner configuration missing")
		}

		var runnerConfig map[string]RunnerConfiguration

		err := json.Unmarshal([]byte(runnerCfg), &runnerConfig)
		if err != nil {
			slog.Error("invalid RUNNER_CONFIGURATION JSON", "error", err.Error())

			return events.APIGatewayProxyResponse{
				StatusCode: http.StatusInternalServerError,
			}, fmt.Errorf("RUNNER_CONFIGURATION contains invalid JSON: %w", err)
		}

		region := cmp.Or(os.Getenv("AWS_DEFAULT_REGION"), os.Getenv("AWS_REGION"))

		validInstanceTypes := types.InstanceTypeC7aLarge.Values()

		// Candidate instance types to try, in the order the labels appear on the
		// job. Trying several lets the launch fall back when a type is out of
		// capacity (InsufficientInstanceCapacity) in every configured subnet.
		var instanceTypes []types.InstanceType

		for _, label := range event.GetWorkflowJob().Labels {
			if _, ok := runnerConfig[label]; ok {
				region = label
			}

			if candidate := types.InstanceType(label); slices.Contains(validInstanceTypes, candidate) &&
				!slices.Contains(instanceTypes, candidate) {
				instanceTypes = append(instanceTypes, candidate)
			}
		}

		if len(instanceTypes) == 0 {
			instanceTypes = []types.InstanceType{types.InstanceTypeC7aLarge}
		}

		regionCfg, ok := runnerConfig[region]
		if !ok {
			return events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError},
				fmt.Errorf("no config for region %s", region)
		}

		if len(regionCfg.SubnetID) == 0 {
			return events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError},
				fmt.Errorf("no subnets configured for region %s", region)
		}

		cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
		if err != nil {
			return events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}, err
		}

		slog.Info("creating runner in region", "region", region)

		svc := ec2.NewFromConfig(cfg)
		sm := secretsmanager.NewFromConfig(cfg)

		secretName := os.Getenv("GITHUB_PAT_SECRET_NAME")
		if secretName == "" {
			slog.Error("GITHUB_PAT_SECRET_NAME env var not set")

			return events.APIGatewayProxyResponse{
					StatusCode: http.StatusInternalServerError,
				}, errors.New(
					"secret name missing",
				)
		}

		secretOut, err := sm.GetSecretValue(
			ctx,
			&secretsmanager.GetSecretValueInput{SecretId: aws.String(secretName)},
		)
		if err != nil {
			slog.Error(
				"failed to get secret", "secret", secretName, "error", err.Error(),
			)

			return events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}, err
		}

		pat := aws.ToString(secretOut.SecretString)

		extraLabels := os.Getenv("EXTRA_RUNNER_LABELS")
		if extraLabels != "" {
			extraLabels = "," + extraLabels
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

		slog.Info("creating instance", "instanceTypes", instanceTypes)

		tpl, err := template.New("userdata").Parse(userData)
		if err != nil {
			return events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}, err
		}

		var buf bytes.Buffer

		err = tpl.Execute(
			&buf,
			map[string]string{"GitHubPAT": pat, "ExtraLabels": extraLabels},
		)
		if err != nil {
			return events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}, err
		}

		finalUserData := buf.String()

		runInput := &ec2.RunInstancesInput{
			MinCount:                          aws.Int32(1),
			MaxCount:                          aws.Int32(1),
			EbsOptimized:                      aws.Bool(true),
			ImageId:                           aws.String(regionCfg.ImageID),
			InstanceInitiatedShutdownBehavior: types.ShutdownBehaviorTerminate,
			// InstanceType is set per-attempt by launchInstance so it can fall
			// back across the candidate instanceTypes on capacity errors.
			IamInstanceProfile: &types.IamInstanceProfileSpecification{
				Arn: aws.String(instanceProfileArn),
			},
			NetworkInterfaces: []types.InstanceNetworkInterfaceSpecification{
				{
					AssociatePublicIpAddress: aws.Bool(true),
					DeleteOnTermination:      aws.Bool(true),
					DeviceIndex:              aws.Int32(0),
					Groups:                   regionCfg.SecurityGroups,
				},
			},
			KeyName:    aws.String(regionCfg.KeyName),
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
		}

		instanceID, err := launchInstance(ctx, svc, runInput, instanceTypes, regionCfg.SubnetID)
		if err != nil {
			slog.Error("failed to launch instance", "error", err.Error())

			return events.APIGatewayProxyResponse{
				Body:       err.Error(),
				StatusCode: http.StatusInternalServerError,
			}, err
		}

		slog.Info("instance created", "instanceID", instanceID)

		return events.APIGatewayProxyResponse{
			Body:       instanceID,
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
