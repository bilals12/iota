package logprocessor

import (
	"strings"

	"github.com/bilals12/iota/pkg/cloudtrail"
)

type Classifier struct {
	eventSourceMap map[string]string
}

func NewClassifier() *Classifier {
	return &Classifier{
		eventSourceMap: buildEventSourceMap(),
	}
}

func (c *Classifier) Classify(event *cloudtrail.Event) string {
	if logType, ok := c.eventSourceMap[event.EventSource]; ok {
		return logType
	}

	if strings.HasPrefix(event.EventSource, "s3.") {
		return "AWS.S3"
	}

	if strings.HasPrefix(event.EventSource, "ec2.") {
		return "AWS.EC2"
	}

	if strings.HasPrefix(event.EventSource, "iam.") {
		return "AWS.IAM"
	}

	return "AWS.CloudTrail"
}

func buildEventSourceMap() map[string]string {
	return map[string]string{
		"cloudtrail.amazonaws.com":           "AWS.CloudTrail",
		"s3.amazonaws.com":                   "AWS.S3",
		"ec2.amazonaws.com":                  "AWS.EC2",
		"iam.amazonaws.com":                  "AWS.IAM",
		"sts.amazonaws.com":                  "AWS.STS",
		"kms.amazonaws.com":                  "AWS.KMS",
		"lambda.amazonaws.com":               "AWS.Lambda",
		"rds.amazonaws.com":                  "AWS.RDS",
		"dynamodb.amazonaws.com":             "AWS.DynamoDB",
		"logs.amazonaws.com":                 "AWS.CloudWatchLogs",
		"guardduty.amazonaws.com":            "AWS.GuardDuty",
		"config.amazonaws.com":               "AWS.Config",
		"cloudformation.amazonaws.com":        "AWS.CloudFormation",
		"elasticloadbalancing.amazonaws.com":  "AWS.ELB",
		"redshift.amazonaws.com":             "AWS.Redshift",
		"ecs.amazonaws.com":                  "AWS.ECS",
		"secretsmanager.amazonaws.com":       "AWS.SecretsManager",
		"ssm.amazonaws.com":                   "AWS.SSM",
	}
}
