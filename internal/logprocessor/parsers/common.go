package parsers

import (
	"strconv"
	"strings"
)

func CsvStringToPointer(s string) *string {
	s = strings.TrimSpace(s)
	if s == "" || s == "-" {
		return nil
	}
	return &s
}

func CsvStringToIntPointer(s string) *int {
	s = strings.TrimSpace(s)
	if s == "" || s == "-" {
		return nil
	}
	val, err := strconv.Atoi(s)
	if err != nil {
		return nil
	}
	return &val
}

func CsvStringToFloat64Pointer(s string) *float64 {
	s = strings.TrimSpace(s)
	if s == "" || s == "-" {
		return nil
	}
	val, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return nil
	}
	return &val
}

func CsvStringToArray(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" || s == "-" {
		return nil
	}
	return strings.Split(s, ",")
}

func LooksLikeCSV(log string) bool {
	return strings.Contains(log, " ") || strings.Contains(log, ",") || strings.Contains(log, "\t")
}
