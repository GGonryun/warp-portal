package logging

import (
	"io"
	"log"
	"os"
	"sync"

	"p0_agent_daemon/config"
)

// DefaultLogPath returns the default log file path from config
var DefaultLogPath = config.LogPath

// LogLevel represents the logging level
type LogLevel int

const (
	LogLevelError LogLevel = iota
	LogLevelWarn
	LogLevelInfo
	LogLevelDebug
	LogLevelTrace
)

var logLevelNames = map[string]LogLevel{
	"error": LogLevelError,
	"warn":  LogLevelWarn,
	"info":  LogLevelInfo,
	"debug": LogLevelDebug,
	"trace": LogLevelTrace,
}

var logLevelStrings = map[LogLevel]string{
	LogLevelError: "ERROR",
	LogLevelWarn:  "WARN",
	LogLevelInfo:  "INFO",
	LogLevelDebug: "DEBUG",
	LogLevelTrace: "TRACE",
}

// Global logger configuration
var (
	globalLogLevel LogLevel = LogLevelInfo
	globalMu       sync.RWMutex
)

func SetGlobalLogLevel(level LogLevel) {
	globalMu.Lock()
	defer globalMu.Unlock()
	globalLogLevel = level
}

func SetGlobalLogLevelFromString(levelStr string) bool {
	if level, exists := logLevelNames[levelStr]; exists {
		SetGlobalLogLevel(level)
		return true
	}
	return false
}

func GetGlobalLogLevel() LogLevel {
	globalMu.RLock()
	defer globalMu.RUnlock()
	return globalLogLevel
}

type Logger struct {
	component string
}

func NewLogger(component string) *Logger {
	return &Logger{
		component: component,
	}
}

func (l *Logger) shouldLog(level LogLevel) bool {
	return GetGlobalLogLevel() >= level
}

func (l *Logger) formatMessage(level LogLevel, format string) string {
	levelStr := logLevelStrings[level]
	if l.component != "" {
		return "[" + levelStr + "] [" + l.component + "] " + format
	}
	return "[" + levelStr + "] " + format
}

func (l *Logger) Error(format string, args ...interface{}) {
	if l.shouldLog(LogLevelError) {
		log.Printf(l.formatMessage(LogLevelError, format), args...)
	}
}

func (l *Logger) Warn(format string, args ...interface{}) {
	if l.shouldLog(LogLevelWarn) {
		log.Printf(l.formatMessage(LogLevelWarn, format), args...)
	}
}

func (l *Logger) Info(format string, args ...interface{}) {
	if l.shouldLog(LogLevelInfo) {
		log.Printf(l.formatMessage(LogLevelInfo, format), args...)
	}
}

func (l *Logger) Debug(format string, args ...interface{}) {
	if l.shouldLog(LogLevelDebug) {
		log.Printf(l.formatMessage(LogLevelDebug, format), args...)
	}
}

func (l *Logger) Trace(format string, args ...interface{}) {
	if l.shouldLog(LogLevelTrace) {
		log.Printf(l.formatMessage(LogLevelTrace, format), args...)
	}
}

func (l *Logger) Fatal(format string, args ...interface{}) {
	log.Printf(l.formatMessage(LogLevelError, format), args...)
	os.Exit(1)
}

func SetupLogging(logPath string) error {
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Printf("[ERROR] Failed to open log file %s, using stdout: %v", logPath, err)
		return err
	}

	multiWriter := io.MultiWriter(os.Stdout, logFile)
	log.SetOutput(multiWriter)
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	log.Printf("Logging to file: %s", logPath)
	return nil
}

func SetupDefaultLogging() error {
	return SetupLogging(DefaultLogPath)
}
