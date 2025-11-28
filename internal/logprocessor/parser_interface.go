package logprocessor

type ParserInterface interface {
	ParseLog(log string) ([]interface{}, error)
	LogType() string
}
