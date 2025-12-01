package parsers

import (
	"fmt"
	"strings"
	"time"

	"github.com/bilals12/iota/internal/logprocessor/parsers/csvstream"
	"github.com/bilals12/iota/internal/logprocessor/parsers/timestamp"
	"github.com/bilals12/iota/pkg/cloudtrail"
)

const (
	albMinNumberOfColumns = 25
)

type ALBParser struct {
	CSVReader *csvstream.StreamingCSVReader
}

func NewALBParser() *ALBParser {
	reader := csvstream.NewStreamingCSVReader()
	reader.CVSReader.Comma = ' '
	return &ALBParser{
		CSVReader: reader,
	}
}

func (p *ALBParser) LogType() string {
	return "AWS.ALB"
}

func (p *ALBParser) ParseLog(log string) ([]*cloudtrail.Event, error) {
	if !LooksLikeCSV(log) {
		return nil, fmt.Errorf("log is not CSV")
	}

	record, err := p.CSVReader.Parse(log)
	if err != nil {
		return nil, fmt.Errorf("parse CSV: %w", err)
	}

	if len(record) < albMinNumberOfColumns {
		return nil, fmt.Errorf("invalid number of columns: got %d, expected at least %d", len(record), albMinNumberOfColumns)
	}

	timeStamp, err := timestamp.Parse(time.RFC3339Nano, record[1])
	if err != nil {
		return nil, fmt.Errorf("parse timestamp: %w", err)
	}

	requestCreationTime, err := timestamp.Parse(time.RFC3339Nano, record[21])
	if err != nil {
		requestCreationTime = timeStamp
	}

	var clientIPPort, targetIPPort []string
	clientIPPort = strings.Split(record[3], ":")
	if len(clientIPPort) != 2 {
		clientIPPort = []string{record[3], "-"}
	}
	targetIPPort = strings.Split(record[4], ":")
	if len(targetIPPort) != 2 {
		targetIPPort = []string{record[4], "-"}
	}

	requestParams := extractRequestParams(record[12])

	albData := map[string]interface{}{
		"type":                   CsvStringToPointer(record[0]),
		"timestamp":              timeStamp.Time(),
		"elb":                    CsvStringToPointer(record[2]),
		"clientIP":               CsvStringToPointer(clientIPPort[0]),
		"clientPort":             CsvStringToIntPointer(clientIPPort[1]),
		"targetIP":               CsvStringToPointer(targetIPPort[0]),
		"targetPort":             CsvStringToIntPointer(targetIPPort[1]),
		"requestProcessingTime":  CsvStringToFloat64Pointer(record[5]),
		"targetProcessingTime":   CsvStringToFloat64Pointer(record[6]),
		"responseProcessingTime": CsvStringToFloat64Pointer(record[7]),
		"elbStatusCode":          CsvStringToIntPointer(record[8]),
		"targetStatusCode":       CsvStringToIntPointer(record[9]),
		"receivedBytes":          CsvStringToIntPointer(record[10]),
		"sentBytes":              CsvStringToIntPointer(record[11]),
		"requestHttpMethod":      CsvStringToPointer(requestParams[0]),
		"requestUrl":             CsvStringToPointer(requestParams[1]),
		"requestHttpVersion":     CsvStringToPointer(requestParams[2]),
		"userAgent":              CsvStringToPointer(record[13]),
		"sslCipher":              CsvStringToPointer(record[14]),
		"sslProtocol":           CsvStringToPointer(record[15]),
		"targetGroupArn":        CsvStringToPointer(record[16]),
		"traceId":                CsvStringToPointer(record[17]),
		"domainName":            CsvStringToPointer(record[18]),
		"chosenCertArn":         CsvStringToPointer(record[19]),
		"matchedRulePriority":   CsvStringToIntPointer(record[20]),
		"requestCreationTime":    requestCreationTime.Time(),
		"actionsExecuted":        CsvStringToArray(record[22]),
		"redirectUrl":            CsvStringToPointer(record[23]),
		"errorReason":            CsvStringToPointer(record[24]),
	}

	eventID := fmt.Sprintf("alb-%s", timeStamp.Time().Format("20060102150405"))
	if elb := CsvStringToPointer(record[2]); elb != nil {
		eventID = fmt.Sprintf("alb-%s-%s", *elb, timeStamp.Time().Format("20060102150405"))
	}

	clientIP := ""
	if ip := CsvStringToPointer(clientIPPort[0]); ip != nil {
		clientIP = *ip
	}

	eventName := "ALBAccess"
	if method := CsvStringToPointer(requestParams[0]); method != nil {
		eventName = fmt.Sprintf("ALB-%s", *method)
	}

	return []*cloudtrail.Event{{
		EventVersion:       "1.0",
		EventTime:          timeStamp.Time(),
		EventSource:        "elasticloadbalancing.amazonaws.com",
		EventName:          eventName,
		AWSRegion:          "",
		SourceIPAddress:    clientIP,
		UserAgent:          "",
		RequestID:          eventID,
		EventID:            eventID,
		EventType:          "AwsApiCall",
		RecipientAccountID: "",
		RequestParameters:  albData,
	}}, nil
}

func extractRequestParams(requestInfo string) [3]string {
	segments := strings.Split(requestInfo, " ")
	segmentCount := len(segments)

	var requestParams [3]string
	if segmentCount < 3 {
		return requestParams
	}

	requestParams[0] = segments[0]
	requestParams[2] = segments[segmentCount-1]

	if segmentCount == 3 {
		requestParams[1] = segments[1]
	} else {
		requestParams[1] = strings.Join(segments[1:segmentCount-1], " ")
	}

	return requestParams
}

var _ ParserInterface = (*ALBParser)(nil)
