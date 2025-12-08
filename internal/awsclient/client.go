package awsclient

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/google/uuid"
)

var SessionNamespace = uuid.MustParse("6ba7b810-9dad-11d1-80b4-00c04fd430c8")

type ClientFactory struct {
	baseConfig    aws.Config
	stsClient     *sts.Client
	sessionSecret string
}

type RefreshableCredentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	SessionName     string
	Expiration      time.Time
}

func NewClientFactory(ctx context.Context, region string) (*ClientFactory, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("load default config: %w", err)
	}

	secret := os.Getenv("IOTA_SESSION_SECRET")
	if secret == "" {
		secret = uuid.New().String()
	}

	return &ClientFactory{
		baseConfig:    cfg,
		stsClient:     sts.NewFromConfig(cfg),
		sessionSecret: secret,
	}, nil
}

func (f *ClientFactory) generateSessionName() string {
	ts := time.Now().UTC().Format(time.RFC3339)
	return uuid.NewSHA1(SessionNamespace, []byte(ts+f.sessionSecret)).String()
}

func (f *ClientFactory) ValidateSessionName(sessionName string, timestamp time.Time) bool {
	ts := timestamp.UTC().Format(time.RFC3339)
	expected := uuid.NewSHA1(SessionNamespace, []byte(ts+f.sessionSecret)).String()
	return sessionName == expected
}

func (f *ClientFactory) assumeRole(ctx context.Context, roleARN string) (*sts.AssumeRoleOutput, string, error) {
	sessionName := f.generateSessionName()
	result, err := f.stsClient.AssumeRole(ctx, &sts.AssumeRoleInput{
		RoleArn:         aws.String(roleARN),
		RoleSessionName: aws.String(sessionName),
		DurationSeconds: aws.Int32(3600),
	})
	if err != nil {
		return nil, "", fmt.Errorf("assume role: %w", err)
	}
	return result, sessionName, nil
}

func (f *ClientFactory) GetS3Client(ctx context.Context, roleARN string) (*s3.Client, error) {
	if roleARN == "" {
		return s3.NewFromConfig(f.baseConfig), nil
	}

	result, _, err := f.assumeRole(ctx, roleARN)
	if err != nil {
		return nil, err
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

func (f *ClientFactory) AssumeRole(ctx context.Context, roleARN string) (*RefreshableCredentials, error) {
	result, sessionName, err := f.assumeRole(ctx, roleARN)
	if err != nil {
		return nil, err
	}

	return &RefreshableCredentials{
		AccessKeyID:     aws.ToString(result.Credentials.AccessKeyId),
		SecretAccessKey: aws.ToString(result.Credentials.SecretAccessKey),
		SessionToken:    aws.ToString(result.Credentials.SessionToken),
		SessionName:     sessionName,
		Expiration:      aws.ToTime(result.Credentials.Expiration),
	}, nil
}
