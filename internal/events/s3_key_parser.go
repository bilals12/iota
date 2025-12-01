package events

import (
	"fmt"
	"path"
	"regexp"
	"strings"
)

var (
	cloudTrailLogRegex = regexp.MustCompile(`^(\d{12})_CloudTrail_([^_]+)_\d{8}T\d{4}Z_\w+\.json(\.gz)?$`)
)

type S3KeyInfo struct {
	AccountID string
	Region    string
	IsValid   bool
}

func ParseCloudTrailS3Key(key string) (*S3KeyInfo, error) {
	parts := strings.Split(strings.TrimPrefix(key, "AWSLogs/"), "/")

	if len(parts) < 4 {
		return &S3KeyInfo{IsValid: false}, nil
	}

	var accountID, region string
	var accountIdx int

	if strings.HasPrefix(parts[0], "o-") {
		if len(parts) < 5 {
			return &S3KeyInfo{IsValid: false}, nil
		}
		accountIdx = 1
	} else {
		accountIdx = 0
	}

	if accountIdx+3 >= len(parts) {
		return &S3KeyInfo{IsValid: false}, nil
	}

	if parts[accountIdx+1] != "CloudTrail" {
		return &S3KeyInfo{IsValid: false}, nil
	}

	accountID = parts[accountIdx]
	region = parts[accountIdx+2]

	if accountID == "" || region == "" {
		return &S3KeyInfo{IsValid: false}, nil
	}

	filename := path.Base(key)
	if !cloudTrailLogRegex.MatchString(filename) {
		return &S3KeyInfo{IsValid: false}, nil
	}

	return &S3KeyInfo{
		AccountID: accountID,
		Region:    region,
		IsValid:   true,
	}, nil
}

func ExtractAccountRegionFromKey(key string) (accountID, region string, err error) {
	info, err := ParseCloudTrailS3Key(key)
	if err != nil {
		return "", "", fmt.Errorf("parse s3 key: %w", err)
	}

	if !info.IsValid {
		return "", "", fmt.Errorf("invalid cloudtrail s3 key format: %s", key)
	}

	return info.AccountID, info.Region, nil
}
