package athena

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/athena"
	"github.com/aws/aws-sdk-go-v2/service/athena/types"
)

type Client struct {
	athenaClient *athena.Client
	workgroup    string
	database     string
	resultBucket string
}

func New(athenaClient *athena.Client, workgroup, database, resultBucket string) *Client {
	return &Client{
		athenaClient: athenaClient,
		workgroup:    workgroup,
		database:     database,
		resultBucket: resultBucket,
	}
}

func (c *Client) RunQuery(ctx context.Context, sql string) (*athena.GetQueryResultsOutput, error) {
	executionID, err := c.StartQuery(ctx, sql)
	if err != nil {
		return nil, fmt.Errorf("start query: %w", err)
	}

	return c.WaitForResults(ctx, executionID)
}

func (c *Client) StartQuery(ctx context.Context, sql string) (string, error) {
	resultLocation := fmt.Sprintf("s3://%s/query-results/", c.resultBucket)

	input := &athena.StartQueryExecutionInput{
		QueryString: aws.String(sql),
		QueryExecutionContext: &types.QueryExecutionContext{
			Database: aws.String(c.database),
		},
		WorkGroup: aws.String(c.workgroup),
		ResultConfiguration: &types.ResultConfiguration{
			OutputLocation: aws.String(resultLocation),
		},
	}

	output, err := c.athenaClient.StartQueryExecution(ctx, input)
	if err != nil {
		return "", fmt.Errorf("start query execution: %w", err)
	}

	return *output.QueryExecutionId, nil
}

func (c *Client) WaitForResults(ctx context.Context, queryExecutionID string) (*athena.GetQueryResultsOutput, error) {
	pollInterval := 2 * time.Second
	maxWaitTime := 5 * time.Minute
	deadline := time.Now().Add(maxWaitTime)

	for time.Now().Before(deadline) {
		status, err := c.athenaClient.GetQueryExecution(ctx, &athena.GetQueryExecutionInput{
			QueryExecutionId: aws.String(queryExecutionID),
		})
		if err != nil {
			return nil, fmt.Errorf("get query execution: %w", err)
		}

		state := status.QueryExecution.Status.State
		switch state {
		case types.QueryExecutionStateSucceeded:
			results, err := c.athenaClient.GetQueryResults(ctx, &athena.GetQueryResultsInput{
				QueryExecutionId: aws.String(queryExecutionID),
			})
			if err != nil {
				return nil, fmt.Errorf("get query results: %w", err)
			}
			return results, nil

		case types.QueryExecutionStateFailed:
			reason := ""
			if status.QueryExecution.Status.StateChangeReason != nil {
				reason = *status.QueryExecution.Status.StateChangeReason
			}
			return nil, fmt.Errorf("query failed: %s", reason)

		case types.QueryExecutionStateCancelled:
			return nil, fmt.Errorf("query cancelled")

		case types.QueryExecutionStateQueued, types.QueryExecutionStateRunning:
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(pollInterval):
				continue
			}
		}
	}

	return nil, fmt.Errorf("query timeout after %v", maxWaitTime)
}

func (c *Client) GetQueryStatus(ctx context.Context, queryExecutionID string) (*types.QueryExecutionStatus, error) {
	status, err := c.athenaClient.GetQueryExecution(ctx, &athena.GetQueryExecutionInput{
		QueryExecutionId: aws.String(queryExecutionID),
	})
	if err != nil {
		return nil, fmt.Errorf("get query execution: %w", err)
	}

	return status.QueryExecution.Status, nil
}
