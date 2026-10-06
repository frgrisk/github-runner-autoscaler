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

var userDataTemplate = template.Must(template.New("userdata").Parse(userData))

var validInstanceTypes = types.InstanceTypeC7aLarge.Values()

type RunnerConfiguration struct {
	ImageID        string   `json:"ami"`
	SubnetID       []string `json:"subnet"`
	SecurityGroups []string `json:"sg"`
	KeyName        string   `json:"key"`
}

// jobIDTagKey tags each runner instance with the ID of the job it was launched
// for, and the reconciler counts a job's launches by it. Changing it hides
// instances tagged under the old key, so their jobs get duplicate runners until
// EC2 stops listing them.
const jobIDTagKey = "GitHub Workflow Job Event ID"

// ephemeralLabel marks jobs this autoscaler launches runners for.
const ephemeralLabel = "ephemeral"

// queued is GitHub's workflow_job action, and run and job status, for work
// waiting on a runner.
const queued = "queued"

func jobIDTagValue(jobID int64) string {
	return strconv.FormatInt(jobID, 10)
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
			runInput.NetworkInterfaces[0].SubnetId = new(subnet)

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

// launchSettings is the deployment configuration the function reads from its
// environment.
type launchSettings struct {
	runnerConfig       map[string]RunnerConfiguration
	defaultRegion      string
	secretName         string
	extraLabels        []string
	instanceProfileArn string
}

func loadLaunchSettings() (launchSettings, error) {
	runnerCfg := os.Getenv("RUNNER_CONFIGURATION")
	if runnerCfg == "" {
		return launchSettings{}, errors.New("RUNNER_CONFIGURATION env var not set")
	}

	var runnerConfig map[string]RunnerConfiguration

	err := json.Unmarshal([]byte(runnerCfg), &runnerConfig)
	if err != nil {
		return launchSettings{}, fmt.Errorf("RUNNER_CONFIGURATION contains invalid JSON: %w", err)
	}

	secretName := os.Getenv("GITHUB_PAT_SECRET_NAME")
	if secretName == "" {
		return launchSettings{}, errors.New("GITHUB_PAT_SECRET_NAME env var not set")
	}

	instanceProfileArn := os.Getenv("INSTANCE_PROFILE_ARN")
	if instanceProfileArn == "" {
		return launchSettings{}, errors.New("INSTANCE_PROFILE_ARN env var not set")
	}

	return launchSettings{
		runnerConfig:       runnerConfig,
		defaultRegion:      cmp.Or(os.Getenv("AWS_DEFAULT_REGION"), os.Getenv("AWS_REGION")),
		secretName:         secretName,
		extraLabels:        splitList(os.Getenv("EXTRA_RUNNER_LABELS")),
		instanceProfileArn: instanceProfileArn,
	}, nil
}

// splitList parses a comma separated setting, dropping blank entries.
func splitList(s string) []string {
	var items []string

	for item := range strings.SplitSeq(s, ",") {
		if item = strings.TrimSpace(item); item != "" {
			items = append(items, item)
		}
	}

	return items
}

// placement picks the region and candidate instance types for a job from its
// labels. A label naming a configured region selects it, otherwise the
// function's own region is used. Instance types are tried in the order the
// labels appear on the job, which lets a launch fall back when a type is out of
// capacity (InsufficientInstanceCapacity) in every configured subnet.
func (s launchSettings) placement(labels []string) (string, []types.InstanceType) {
	region := s.defaultRegion

	var instanceTypes []types.InstanceType

	for _, label := range labels {
		if _, ok := s.runnerConfig[label]; ok {
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

	return region, instanceTypes
}

// registeredLabels are the labels user-data.sh registers a runner in region
// with, besides its instance type. That one is read from instance metadata
// because launchInstance may fall back to another type after rendering.
func (s launchSettings) registeredLabels(region string) []string {
	return append([]string{ephemeralLabel, "X64", region}, s.extraLabels...)
}

func (s launchSettings) userData(pat, region string) ([]byte, error) {
	var buf bytes.Buffer

	err := userDataTemplate.Execute(&buf, map[string]string{
		"GitHubPAT": pat,
		"Labels":    strings.Join(s.registeredLabels(region), ","),
	})

	return buf.Bytes(), err
}

func fetchPAT(ctx context.Context, cfg aws.Config, secretName string) (string, error) {
	secretOut, err := secretsmanager.NewFromConfig(cfg).GetSecretValue(
		ctx,
		&secretsmanager.GetSecretValueInput{SecretId: new(secretName)},
	)
	if err != nil {
		return "", fmt.Errorf("failed to get secret %s: %w", secretName, err)
	}

	return aws.ToString(secretOut.SecretString), nil
}

// launchRunner starts an instance that registers an ephemeral runner for a job
// with these labels, tagged with the job's ID, and returns the instance ID. Only
// cfg's credentials are used: the instance is launched, and the PAT read, in the
// region placement picks from the labels.
func (s launchSettings) launchRunner(
	ctx context.Context,
	cfg aws.Config,
	jobID int64,
	labels []string,
) (string, error) {
	region, instanceTypes := s.placement(labels)

	regionCfg, ok := s.runnerConfig[region]
	if !ok {
		return "", fmt.Errorf("no config for region %s", region)
	}

	if len(regionCfg.SubnetID) == 0 {
		return "", fmt.Errorf("no subnets configured for region %s", region)
	}

	cfg.Region = region

	slog.Info("creating runner in region", "region", region)

	svc := ec2.NewFromConfig(cfg, func(o *ec2.Options) {
		o.Retryer = newEC2Retryer()
	})

	pat, err := fetchPAT(ctx, cfg, s.secretName)
	if err != nil {
		return "", err
	}

	tags := []types.Tag{
		{
			Key:   new(jobIDTagKey),
			Value: new(jobIDTagValue(jobID)),
		},
		{
			Key:   new("Name"),
			Value: new("GitHub Workflow Ephemeral Runner"),
		},
	}

	slog.Info("creating instance", "instanceTypes", instanceTypes)

	script, err := s.userData(pat, region)
	if err != nil {
		return "", err
	}

	runInput := &ec2.RunInstancesInput{
		MinCount:                          new(int32(1)),
		MaxCount:                          new(int32(1)),
		EbsOptimized:                      new(true),
		ImageId:                           new(regionCfg.ImageID),
		InstanceInitiatedShutdownBehavior: types.ShutdownBehaviorTerminate,
		// InstanceType is set per-attempt by launchInstance so it can fall
		// back across the candidate instanceTypes on capacity errors.
		IamInstanceProfile: &types.IamInstanceProfileSpecification{
			Arn: new(s.instanceProfileArn),
		},
		NetworkInterfaces: []types.InstanceNetworkInterfaceSpecification{
			{
				AssociatePublicIpAddress: new(true),
				DeleteOnTermination:      new(true),
				DeviceIndex:              new(int32(0)),
				Groups:                   regionCfg.SecurityGroups,
			},
		},
		KeyName:    new(regionCfg.KeyName),
		Monitoring: &types.RunInstancesMonitoringEnabled{Enabled: new(true)},
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
		UserData: new(base64.StdEncoding.EncodeToString(script)),
	}

	instanceID, err := launchInstance(ctx, svc, runInput, instanceTypes, regionCfg.SubnetID)
	if err != nil {
		return "", err
	}

	slog.Info("instance created", "instanceID", instanceID, "jobID", jobID)

	return instanceID, nil
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
		if event.GetAction() != queued {
			slog.Info("not a queued job event")

			return events.APIGatewayProxyResponse{StatusCode: http.StatusOK}, nil
		}

		job := event.GetWorkflowJob()

		if !slices.Contains(job.Labels, ephemeralLabel) {
			slog.Info("not ephemeral")

			return events.APIGatewayProxyResponse{StatusCode: http.StatusOK}, nil
		}

		settings, err := loadLaunchSettings()
		if err != nil {
			slog.Error("invalid configuration", "error", err.Error())

			return events.APIGatewayProxyResponse{
				StatusCode: http.StatusInternalServerError,
			}, err
		}

		cfg, err := config.LoadDefaultConfig(ctx)
		if err != nil {
			slog.Error("failed to load AWS config", "error", err.Error())

			return events.APIGatewayProxyResponse{
				StatusCode: http.StatusInternalServerError,
			}, err
		}

		instanceID, err := settings.launchRunner(ctx, cfg, job.GetID(), job.Labels)
		if err != nil {
			slog.Error("failed to launch instance", "error", err.Error())

			return events.APIGatewayProxyResponse{
				Body:       err.Error(),
				StatusCode: http.StatusInternalServerError,
			}, err
		}

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
	// Both functions in template.yaml run this binary. Without
	// AUTOSCALER_MODE=reconcile, RunnerReconcilerFunction's scheduled events
	// reach handler, which ignores them, and no job is reconciled.
	if os.Getenv("AUTOSCALER_MODE") == "reconcile" {
		lambda.Start(reconcile)

		return
	}

	lambda.Start(handler)
}
