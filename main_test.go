package main

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

type mockEC2Client struct {
	input *ec2.RunInstancesInput
}

func (m *mockEC2Client) RunInstances(ctx context.Context, params *ec2.RunInstancesInput, optFns ...func(*ec2.Options)) (*ec2.RunInstancesOutput, error) {
	m.input = params
	return &ec2.RunInstancesOutput{
		Instances: []types.Instance{{InstanceId: aws.String("i-1234567890")}},
	}, nil
}

func TestHandlerQueuedEvent(t *testing.T) {
	origNew := newEC2Client
	origLoad := loadAWSConfig
	defer func() {
		newEC2Client = origNew
		loadAWSConfig = origLoad
	}()

	mockSvc := &mockEC2Client{}
	newEC2Client = func(cfg aws.Config) ec2RunInstancesAPI { return mockSvc }
	loadAWSConfig = func(ctx context.Context, optFns ...func(*config.LoadOptions) error) (aws.Config, error) {
		return aws.Config{}, nil
	}

	eventJSON := `{"action":"queued","workflow_job":{"id":1,"labels":["ephemeral"]}}`
	encoded := base64.StdEncoding.EncodeToString([]byte(eventJSON))

	req := events.APIGatewayProxyRequest{
		Body:            encoded,
		IsBase64Encoded: true,
		MultiValueHeaders: map[string][]string{
			"X-GitHub-Event": {"workflow_job"},
		},
	}

	resp, err := handler(req)
	if err != nil {
		t.Fatalf("handler returned error: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("unexpected status %d", resp.StatusCode)
	}
	if mockSvc.input == nil {
		t.Fatal("RunInstances not called")
	}
	if resp.Body != "i-1234567890" {
		t.Fatalf("unexpected body %s", resp.Body)
	}
}
