package awsclient

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type ClientFactory struct {
	baseConfig aws.Config
	stsClient  *sts.Client
}

func NewClientFactory(ctx context.Context, region string) (*ClientFactory, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("load default config: %w", err)
	}

	return &ClientFactory{
		baseConfig: cfg,
		stsClient:  sts.NewFromConfig(cfg),
	}, nil
}

func (f *ClientFactory) GetS3Client(ctx context.Context, roleARN string) (*s3.Client, error) {
	if roleARN == "" {
		return s3.NewFromConfig(f.baseConfig), nil
	}

	result, err := f.stsClient.AssumeRole(ctx, &sts.AssumeRoleInput{
		RoleArn:         aws.String(roleARN),
		RoleSessionName: aws.String("iota-session"),
		DurationSeconds: aws.Int32(3600),
	})
	if err != nil {
		return nil, fmt.Errorf("assume role: %w", err)
	}

	cfg := f.baseConfig.Copy()
	cfg.Credentials = credentials.NewStaticCredentialsProvider(
		aws.ToString(result.Credentials.AccessKeyId),
		aws.ToString(result.Credentials.SecretAccessKey),
		aws.ToString(result.Credentials.SessionToken),
	)

	return s3.NewFromConfig(cfg), nil
}

func (f *ClientFactory) GetS3ClientForAccount(ctx context.Context, accountID, roleARN string) (*s3.Client, error) {
	return f.GetS3Client(ctx, roleARN)
}

type RefreshableCredentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Expiration      time.Time
}

func (f *ClientFactory) AssumeRole(ctx context.Context, roleARN string) (*RefreshableCredentials, error) {
	result, err := f.stsClient.AssumeRole(ctx, &sts.AssumeRoleInput{
		RoleArn:         aws.String(roleARN),
		RoleSessionName: aws.String("iota-session"),
		DurationSeconds: aws.Int32(3600),
	})
	if err != nil {
		return nil, fmt.Errorf("assume role: %w", err)
	}

	return &RefreshableCredentials{
		AccessKeyID:     aws.ToString(result.Credentials.AccessKeyId),
		SecretAccessKey: aws.ToString(result.Credentials.SecretAccessKey),
		SessionToken:    aws.ToString(result.Credentials.SessionToken),
		Expiration:      aws.ToTime(result.Credentials.Expiration),
	}, nil
}
