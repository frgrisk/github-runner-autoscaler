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
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"text/template"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
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

// launchCycleErrorCodes are EC2 error codes for which launching the runner in
// the next configured subnet (potentially a different AZ) or the next candidate
// instance type may succeed. launchInstance handles these itself by cycling to
// the next subnet/type, so excludeLaunchCycleErrors also marks them
// non-retryable on the client (see there for why).
var launchCycleErrorCodes = []string{
	"InsufficientFreeAddressesInSubnet",
	"InsufficientInstanceCapacity",
	"InvalidSubnetID.NotFound",
	"Unsupported",
}

// isLaunchCycleError reports whether err is one launchInstance handles by moving
// on to the next subnet/instance type, rather than a fatal error or a throttle
// the SDK's retryer already backed off and retried.
func isLaunchCycleError(err error) bool {
	apiErr, ok := errors.AsType[smithy.APIError](err)

	return ok && slices.Contains(launchCycleErrorCodes, apiErr.ErrorCode())
}

// excludeLaunchCycleErrors keeps the SDK retryer from retrying the errors that
// launchInstance handles by cycling to the next subnet/instance type.
// InsufficientInstanceCapacity is an HTTP 500, so the default retryer would
// otherwise burn its own attempts (with backoff) retrying the same subnet before
// launchInstance ever gets to try the next one. Returning FalseTernary here
// short-circuits that so the error surfaces immediately; throttling and other
// transient errors fall through to UnknownTernary and keep default retry.
var excludeLaunchCycleErrors = retry.IsErrorRetryableFunc(func(err error) aws.Ternary {
	if isLaunchCycleError(err) {
		return aws.FalseTernary
	}

	return aws.UnknownTernary
})

// newEC2Retryer returns the SDK's standard retryer (throttle + transient backoff
// left at defaults) with cycle errors excluded so launchInstance can move to the
// next subnet/type without waiting on same-call retries.
func newEC2Retryer() *retry.Standard {
	return retry.NewStandard(func(o *retry.StandardOptions) {
		o.Retryables = append(
			[]retry.IsErrorRetryable{excludeLaunchCycleErrors},
			retry.DefaultRetryables...,
		)
	})
}

// launchInstance attempts to launch a runner across the candidate instance types
// and subnets. It tries each instance type in turn, sweeping every subnet; a
// capacity or subnet error (see retryableLaunchErrors) moves straight on to the
// next subnet, then the next type, so a type that is out of capacity in every AZ
// falls through to the next candidate. Throttling and other transient errors are
// backed off and retried by the EC2 client's own retryer before they reach here,
// so any error that is not a cycle error is treated as fatal. It returns the
// launched instance ID, or an error if no type/subnet combination succeeds.
func launchInstance(
	ctx context.Context,
	svc *ec2.Client,
	runInput *ec2.RunInstancesInput,
	instanceTypes []types.InstanceType,
	subnets []string,
) (string, error) {
	var lastErr error

	for _, instanceType := range instanceTypes {
		runInput.InstanceType = instanceType

		for _, subnet := range subnets {
			runInput.NetworkInterfaces[0].SubnetId = aws.String(subnet)

			output, err := svc.RunInstances(ctx, runInput)
			if err != nil {
				if !isLaunchCycleError(err) {
					slog.Error("failed to run instances", "error", err.Error())

					return "", err
				}

				slog.Warn(
					"capacity/subnet error, trying next",
					"instanceType", instanceType,
					"subnet", subnet,
					"error", err.Error(),
				)

				lastErr = err

				continue
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

	if lastErr == nil {
		lastErr = errors.New("failed to launch instance in any subnet")
	}

	return "", fmt.Errorf("failed to launch instance: %w", lastErr)
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

			candidate := types.InstanceType(label)
			if slices.Contains(validInstanceTypes, candidate) &&
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

		svc := ec2.NewFromConfig(cfg, func(o *ec2.Options) {
			o.Retryer = newEC2Retryer()
		})
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
