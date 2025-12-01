package parsers

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/bilals12/iota/internal/logprocessor/parsers/csvstream"
	"github.com/bilals12/iota/internal/logprocessor/parsers/timestamp"
	"github.com/bilals12/iota/pkg/cloudtrail"
)

const (
	auroraMySQLAuditMinNumberOfColumns = 9
)

type AuroraMySQLAuditParser struct {
	CSVReader *csvstream.StreamingCSVReader
}

func NewAuroraMySQLAuditParser() *AuroraMySQLAuditParser {
	return &AuroraMySQLAuditParser{
		CSVReader: csvstream.NewStreamingCSVReader(),
	}
}

func (p *AuroraMySQLAuditParser) LogType() string {
	return "AWS.AuroraMySQLAudit"
}

func (p *AuroraMySQLAuditParser) ParseLog(log string) ([]*cloudtrail.Event, error) {
	record, err := p.CSVReader.Parse(log)
	if err != nil {
		return nil, fmt.Errorf("parse CSV: %w", err)
	}

	if len(record) < auroraMySQLAuditMinNumberOfColumns {
		return nil, fmt.Errorf("invalid number of columns: got %d, expected at least %d", len(record), auroraMySQLAuditMinNumberOfColumns)
	}

	timestampUnixMillis, err := strconv.ParseInt(record[0], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("parse timestamp: %w", err)
	}

	objectString := strings.Join(record[8:len(record)-1], ",")
	timeStamp := timestamp.Unix(timestampUnixMillis/1000000, timestampUnixMillis%1000000*1000)

	auroraData := map[string]interface{}{
		"timestamp":    timeStamp.Time(),
		"serverHost":   CsvStringToPointer(record[1]),
		"username":     CsvStringToPointer(record[2]),
		"host":         CsvStringToPointer(record[3]),
		"connectionId": CsvStringToIntPointer(record[4]),
		"queryId":      CsvStringToIntPointer(record[5]),
		"operation":    CsvStringToPointer(record[6]),
		"database":    CsvStringToPointer(record[7]),
		"object":      CsvStringToPointer(objectString),
		"retCode":     CsvStringToIntPointer(record[len(record)-1]),
	}

	eventID := fmt.Sprintf("aurora-%s", timeStamp.Time().Format("20060102150405"))
	if connID := CsvStringToIntPointer(record[4]); connID != nil {
		eventID = fmt.Sprintf("aurora-%d-%s", *connID, timeStamp.Time().Format("20060102150405"))
	}

	host := ""
	if h := CsvStringToPointer(record[3]); h != nil {
		host = *h
	}

	eventName := "AuroraMySQLAudit"
	if op := CsvStringToPointer(record[6]); op != nil {
		eventName = fmt.Sprintf("AuroraMySQL-%s", *op)
	}

	return []*cloudtrail.Event{{
		EventVersion:       "1.0",
		EventTime:          timeStamp.Time(),
		EventSource:        "rds.amazonaws.com",
		EventName:          eventName,
		AWSRegion:          "",
		SourceIPAddress:    host,
		UserAgent:          "",
		RequestID:          eventID,
		EventID:            eventID,
		EventType:          "AwsApiCall",
		RecipientAccountID: "",
		RequestParameters:  auroraData,
	}}, nil
}

var _ ParserInterface = (*AuroraMySQLAuditParser)(nil)
