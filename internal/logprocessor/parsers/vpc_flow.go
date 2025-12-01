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
	vpcFlowHeaderThreshold = 5
)

var vpcFlowHeaders = map[string]struct{}{
	"version":      {},
	"account-id":   {},
	"interface-id": {},
	"srcaddr":      {},
	"dstaddr":      {},
	"srcport":      {},
	"dstport":      {},
	"protocol":    {},
	"packets":      {},
	"bytes":        {},
	"start":        {},
	"end":          {},
	"action":       {},
	"log-status":   {},
	"vpc-id":       {},
	"subnet-id":    {},
	"instance-id":  {},
	"tcp-flags":    {},
	"type":         {},
	"pkt-srcaddr":  {},
	"pkt-dstaddr":  {},
}

type VPCFlowParser struct {
	CSVReader *csvstream.StreamingCSVReader
	columnMap map[int]string
}

func NewVPCFlowParser() *VPCFlowParser {
	reader := csvstream.NewStreamingCSVReader()
	reader.CVSReader.Comma = ' '
	return &VPCFlowParser{
		CSVReader: reader,
	}
}

func (p *VPCFlowParser) LogType() string {
	return "AWS.VPCFlow"
}

func (p *VPCFlowParser) ParseLog(log string) ([]*cloudtrail.Event, error) {
	if !LooksLikeCSV(log) {
		return nil, fmt.Errorf("log is not CSV")
	}

	if p.columnMap == nil {
		if !p.inspectVPCFlowHeader(log) {
			return nil, fmt.Errorf("invalid VPC Flow header")
		}
		return nil, nil
	}

	record, err := p.CSVReader.Parse(log)
	if err != nil {
		return nil, fmt.Errorf("parse CSV: %w", err)
	}

	event := p.populateEvent(record)
	if event == nil {
		return nil, fmt.Errorf("failed to populate event")
	}

	return []*cloudtrail.Event{event}, nil
}

func (p *VPCFlowParser) inspectVPCFlowHeader(log string) bool {
	headers := strings.Split(log, " ")
	matchCount := 0
	for _, header := range headers {
		header = strings.TrimSpace(header)
		if _, exists := vpcFlowHeaders[header]; exists {
			matchCount++
		}
	}

	if matchCount < vpcFlowHeaderThreshold {
		return false
	}

	p.columnMap = make(map[int]string, len(headers))
	for i, header := range headers {
		header = strings.TrimSpace(header)
		p.columnMap[i] = header
	}

	return true
}

func (p *VPCFlowParser) populateEvent(columns []string) *cloudtrail.Event {
	vpcData := make(map[string]interface{})
	var startTime, endTime *timestamp.RFC3339

	for i := range columns {
		if i >= len(columns) {
			break
		}
		header, exists := p.columnMap[i]
		if !exists {
			continue
		}

		value := strings.TrimSpace(columns[i])
		if value == "" || value == "-" {
			continue
		}

		switch header {
		case "version":
			if v := CsvStringToIntPointer(value); v != nil {
				vpcData["version"] = v
			}
		case "account-id":
			vpcData["accountId"] = CsvStringToPointer(value)
		case "interface-id":
			vpcData["interfaceId"] = CsvStringToPointer(value)
		case "srcaddr":
			vpcData["srcAddr"] = CsvStringToPointer(value)
		case "dstaddr":
			vpcData["dstAddr"] = CsvStringToPointer(value)
		case "srcport":
			if v := CsvStringToIntPointer(value); v != nil {
				vpcData["srcPort"] = v
			}
		case "dstport":
			if v := CsvStringToIntPointer(value); v != nil {
				vpcData["dstPort"] = v
			}
		case "protocol":
			if v := CsvStringToIntPointer(value); v != nil {
				vpcData["protocol"] = v
			}
		case "packets":
			if v := CsvStringToIntPointer(value); v != nil {
				vpcData["packets"] = v
			}
		case "bytes":
			if v := CsvStringToIntPointer(value); v != nil {
				vpcData["bytes"] = v
			}
		case "start":
			if t, err := strconv.ParseInt(value, 10, 64); err == nil {
				ts := timestamp.Unix(t, 0)
				startTime = &ts
				vpcData["start"] = ts.Time()
			}
		case "end":
			if t, err := strconv.ParseInt(value, 10, 64); err == nil {
				ts := timestamp.Unix(t, 0)
				endTime = &ts
				vpcData["end"] = ts.Time()
			}
		case "action":
			vpcData["action"] = CsvStringToPointer(value)
		case "log-status":
			vpcData["logStatus"] = CsvStringToPointer(value)
		case "vpc-id":
			vpcData["vpcId"] = CsvStringToPointer(value)
		case "subnet-id":
			vpcData["subnetId"] = CsvStringToPointer(value)
		case "instance-id":
			vpcData["instanceId"] = CsvStringToPointer(value)
		case "tcp-flags":
			if v := CsvStringToIntPointer(value); v != nil {
				vpcData["tcpFlags"] = v
			}
		case "type":
			vpcData["type"] = CsvStringToPointer(value)
		case "pkt-srcaddr":
			vpcData["pktSrcAddr"] = CsvStringToPointer(value)
		case "pkt-dstaddr":
			vpcData["pktDstAddr"] = CsvStringToPointer(value)
		}
	}

	if startTime == nil {
		return nil
	}

	eventTime := startTime.Time()
	if endTime != nil {
		eventTime = endTime.Time()
	}

	eventID := fmt.Sprintf("vpcflow-%s", eventTime.Format("20060102150405"))
	if ifaceID, ok := vpcData["interfaceId"].(*string); ok && ifaceID != nil {
		eventID = fmt.Sprintf("vpcflow-%s-%s", *ifaceID, eventTime.Format("20060102150405"))
	}

	srcAddr := ""
	if addr, ok := vpcData["srcAddr"].(*string); ok && addr != nil {
		srcAddr = *addr
	}

	return &cloudtrail.Event{
		EventVersion:       "1.0",
		EventTime:          eventTime,
		EventSource:        "vpcflowlogs.amazonaws.com",
		EventName:          "VPCFlow",
		AWSRegion:          "",
		SourceIPAddress:    srcAddr,
		UserAgent:          "",
		RequestID:          eventID,
		EventID:            eventID,
		EventType:          "AwsApiCall",
		RecipientAccountID: "",
		RequestParameters:  vpcData,
	}
}

var _ ParserInterface = (*VPCFlowParser)(nil)
