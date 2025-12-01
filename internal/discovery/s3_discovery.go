package discovery

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type AccountRegionPair struct {
	AccountID string
	Region    string
}

func isNumeric(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func DiscoverAccounts(ctx context.Context, s3Client *s3.Client, bucket, basePrefix string) ([]string, string, error) {
	var orgID string
	accountMap := make(map[string]bool)

	input := &s3.ListObjectsV2Input{
		Bucket:    aws.String(bucket),
		Prefix:    aws.String(basePrefix),
		Delimiter: aws.String("/"),
		MaxKeys:   aws.Int32(1000),
	}

	resp, err := s3Client.ListObjectsV2(ctx, input)
	if err != nil {
		return nil, "", fmt.Errorf("list objects: %w", err)
	}

	for _, prefix := range resp.CommonPrefixes {
		parts := strings.Split(strings.TrimSuffix(aws.ToString(prefix.Prefix), "/"), "/")
		if len(parts) >= 1 {
			id := parts[len(parts)-1]

			if strings.HasPrefix(id, "o-") {
				orgID = id
				orgPrefix := basePrefix + id + "/"
				orgInput := &s3.ListObjectsV2Input{
					Bucket:    aws.String(bucket),
					Prefix:    aws.String(orgPrefix),
					Delimiter: aws.String("/"),
					MaxKeys:   aws.Int32(1000),
				}

				orgResp, err := s3Client.ListObjectsV2(ctx, orgInput)
				if err != nil {
					log.Printf("warning: failed to list organization accounts: %v", err)
					continue
				}

				for _, orgPfx := range orgResp.CommonPrefixes {
					orgParts := strings.Split(strings.TrimSuffix(aws.ToString(orgPfx.Prefix), "/"), "/")
					if len(orgParts) >= 1 {
						accountID := orgParts[len(orgParts)-1]
						if len(accountID) == 12 && isNumeric(accountID) {
							accountMap[accountID] = true
						}
					}
				}
			} else if len(id) == 12 && isNumeric(id) {
				accountMap[id] = true
			}
		}
	}

	accounts := make([]string, 0, len(accountMap))
	for account := range accountMap {
		accounts = append(accounts, account)
	}

	return accounts, orgID, nil
}

func DiscoverAccountRegions(ctx context.Context, s3Client *s3.Client, bucket, basePrefix string, accounts []string, orgID string) ([]AccountRegionPair, error) {
	var pairs []AccountRegionPair
	var mu sync.Mutex

	var wg sync.WaitGroup
	for _, accountID := range accounts {
		wg.Add(1)
		go func(acct string) {
			defer wg.Done()

			var prefix string
			if orgID != "" {
				prefix = fmt.Sprintf("%s%s/%s/CloudTrail/", basePrefix, orgID, acct)
			} else {
				prefix = fmt.Sprintf("%s%s/CloudTrail/", basePrefix, acct)
			}

			input := &s3.ListObjectsV2Input{
				Bucket:    aws.String(bucket),
				Prefix:    aws.String(prefix),
				Delimiter: aws.String("/"),
				MaxKeys:   aws.Int32(1000),
			}

			paginator := s3.NewListObjectsV2Paginator(s3Client, input)
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					log.Printf("warning: failed to discover regions for account %s: %v", acct, err)
					break
				}

				for _, commonPrefix := range page.CommonPrefixes {
					parts := strings.Split(strings.TrimSuffix(aws.ToString(commonPrefix.Prefix), "/"), "/")
					for i, part := range parts {
						if part == "CloudTrail" && i+1 < len(parts) {
							region := parts[i+1]
							if region != "" {
								mu.Lock()
								pairs = append(pairs, AccountRegionPair{
									AccountID: acct,
									Region:    region,
								})
								mu.Unlock()
							}
							break
						}
					}
				}
			}
		}(accountID)
	}
	wg.Wait()

	return pairs, nil
}
