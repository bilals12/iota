package parsers

import (
	"fmt"

	"github.com/bilals12/iota/internal/logprocessor/parsers/csvstream"
	"github.com/bilals12/iota/internal/logprocessor/parsers/timestamp"
	"github.com/bilals12/iota/pkg/cloudtrail"
)

const (
	s3ServerAccessMinNumberOfColumns = 25
)

type S3ServerAccessParser struct {
	CSVReader *csvstream.StreamingCSVReader
}

func NewS3ServerAccessParser() *S3ServerAccessParser {
	reader := csvstream.NewStreamingCSVReader()
	reader.CVSReader.Comma = ' '
	return &S3ServerAccessParser{
		CSVReader: reader,
	}
}

func (p *S3ServerAccessParser) LogType() string {
	return "AWS.S3ServerAccess"
}

func (p *S3ServerAccessParser) ParseLog(log string) ([]*cloudtrail.Event, error) {
	if !LooksLikeCSV(log) {
		return nil, fmt.Errorf("log is not CSV")
	}

	record, err := p.CSVReader.Parse(log)
	if err != nil {
		return nil, fmt.Errorf("parse CSV: %w", err)
	}

	if len(record) < s3ServerAccessMinNumberOfColumns {
		return nil, fmt.Errorf("wrong number of columns: got %d, expected at least %d", len(record), s3ServerAccessMinNumberOfColumns)
	}

	parsedTime, err := timestamp.Parse("[2/Jan/2006:15:04:05-0700]", record[2]+record[3])
	if err != nil {
		return nil, fmt.Errorf("parse timestamp: %w", err)
	}

	var additionalFields []string
	if len(record) > 25 {
		additionalFields = record[25:]
	}

	requestID := CsvStringToPointer(record[6])
	operation := CsvStringToPointer(record[7])
	remoteIP := CsvStringToPointer(record[4])
	userAgent := CsvStringToPointer(record[17])

	s3Data := map[string]interface{}{
		"bucketOwner":        CsvStringToPointer(record[0]),
		"bucket":             CsvStringToPointer(record[1]),
		"time":               parsedTime.Time(),
		"remoteIP":           remoteIP,
		"requester":          CsvStringToPointer(record[5]),
		"requestID":          requestID,
		"operation":          operation,
		"key":                CsvStringToPointer(record[8]),
		"requestURI":         CsvStringToPointer(record[9]),
		"httpStatus":         CsvStringToIntPointer(record[10]),
		"errorCode":          CsvStringToPointer(record[11]),
		"bytesSent":          CsvStringToIntPointer(record[12]),
		"objectSize":         CsvStringToIntPointer(record[13]),
		"totalTime":          CsvStringToIntPointer(record[14]),
		"turnAroundTime":     CsvStringToIntPointer(record[15]),
		"referrer":           CsvStringToPointer(record[16]),
		"userAgent":          userAgent,
		"versionID":          CsvStringToPointer(record[18]),
		"hostID":             CsvStringToPointer(record[19]),
		"signatureVersion":   CsvStringToPointer(record[20]),
		"cipherSuite":        CsvStringToPointer(record[21]),
		"authenticationType": CsvStringToPointer(record[22]),
		"hostHeader":         CsvStringToPointer(record[23]),
		"tlsVersion":         CsvStringToPointer(record[24]),
		"additionalFields":   additionalFields,
	}

	eventID := fmt.Sprintf("s3-%s", parsedTime.Time().Format("20060102150405"))
	if requestID != nil {
		eventID = fmt.Sprintf("s3-%s-%s", *requestID, parsedTime.Time().Format("20060102150405"))
	}

	eventName := "S3ServerAccess"
	if operation != nil {
		eventName = *operation
	}

	event := &cloudtrail.Event{
		EventVersion:       "1.0",
		EventTime:          parsedTime.Time(),
		EventSource:        "s3.amazonaws.com",
		EventName:          eventName,
		AWSRegion:          "",
		SourceIPAddress:    "",
		UserAgent:          "",
		RequestID:          eventID,
		EventID:            eventID,
		EventType:          "AwsApiCall",
		RecipientAccountID: "",
		RequestParameters:  s3Data,
	}

	if remoteIP != nil {
		event.SourceIPAddress = *remoteIP
	}
	if userAgent != nil {
		event.UserAgent = *userAgent
	}

	return []*cloudtrail.Event{event}, nil
}

var _ ParserInterface = (*S3ServerAccessParser)(nil)
