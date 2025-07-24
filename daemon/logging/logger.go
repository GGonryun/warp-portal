package logging

import (
	"io"
	"log"
	"os"
	"sync"
	
	"warp_portal_daemon/config"
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

// SetGlobalLogLevel sets the global logging level
func SetGlobalLogLevel(level LogLevel) {
	globalMu.Lock()
	defer globalMu.Unlock()
	globalLogLevel = level
}

// SetGlobalLogLevelFromString sets the global logging level from a string
func SetGlobalLogLevelFromString(levelStr string) bool {
	if level, exists := logLevelNames[levelStr]; exists {
		SetGlobalLogLevel(level)
		return true
	}
	return false
}

// GetGlobalLogLevel returns the current global logging level
func GetGlobalLogLevel() LogLevel {
	globalMu.RLock()
	defer globalMu.RUnlock()
	return globalLogLevel
}

// Logger represents a logger instance with a specific component name
type Logger struct {
	component string
}

// NewLogger creates a new logger instance for a specific component
func NewLogger(component string) *Logger {
	return &Logger{
		component: component,
	}
}

// shouldLog checks if a message at the given level should be logged
func (l *Logger) shouldLog(level LogLevel) bool {
	return GetGlobalLogLevel() >= level
}

// formatMessage formats a log message with component prefix
func (l *Logger) formatMessage(level LogLevel, format string) string {
	levelStr := logLevelStrings[level]
	if l.component != "" {
		return "[" + levelStr + "] [" + l.component + "] " + format
	}
	return "[" + levelStr + "] " + format
}

// Error logs an error message
func (l *Logger) Error(format string, args ...interface{}) {
	if l.shouldLog(LogLevelError) {
		log.Printf(l.formatMessage(LogLevelError, format), args...)
	}
}

// Warn logs a warning message
func (l *Logger) Warn(format string, args ...interface{}) {
	if l.shouldLog(LogLevelWarn) {
		log.Printf(l.formatMessage(LogLevelWarn, format), args...)
	}
}

// Info logs an info message
func (l *Logger) Info(format string, args ...interface{}) {
	if l.shouldLog(LogLevelInfo) {
		log.Printf(l.formatMessage(LogLevelInfo, format), args...)
	}
}

// Debug logs a debug message
func (l *Logger) Debug(format string, args ...interface{}) {
	if l.shouldLog(LogLevelDebug) {
		log.Printf(l.formatMessage(LogLevelDebug, format), args...)
	}
}

// Trace logs a trace message
func (l *Logger) Trace(format string, args ...interface{}) {
	if l.shouldLog(LogLevelTrace) {
		log.Printf(l.formatMessage(LogLevelTrace, format), args...)
	}
}

// Fatal logs a fatal error message and exits the program
func (l *Logger) Fatal(format string, args ...interface{}) {
	log.Printf(l.formatMessage(LogLevelError, format), args...)
	os.Exit(1)
}

// Global convenience functions that use the default logger
var defaultLogger = NewLogger("")

// Error logs an error message using the default logger
func Error(format string, args ...interface{}) {
	defaultLogger.Error(format, args...)
}

// Warn logs a warning message using the default logger
func Warn(format string, args ...interface{}) {
	defaultLogger.Warn(format, args...)
}

// Info logs an info message using the default logger
func Info(format string, args ...interface{}) {
	defaultLogger.Info(format, args...)
}

// Debug logs a debug message using the default logger
func Debug(format string, args ...interface{}) {
	defaultLogger.Debug(format, args...)
}

// Trace logs a trace message using the default logger
func Trace(format string, args ...interface{}) {
	defaultLogger.Trace(format, args...)
}

// Fatal logs a fatal error message using the default logger and exits
func Fatal(format string, args ...interface{}) {
	defaultLogger.Fatal(format, args...)
}

// SetupLogging configures the global Go logger to write to both stdout and a log file
func SetupLogging(logPath string) error {
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Printf("[ERROR] Failed to open log file %s, using stdout: %v", logPath, err)
		return err
	}

	multiWriter := io.MultiWriter(os.Stdout, logFile)
	log.SetOutput(multiWriter)
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	
	Info("Logging to file: %s", logPath)
	return nil
}

// SetupDefaultLogging configures logging using the default log path
func SetupDefaultLogging() error {
	return SetupLogging(DefaultLogPath)
}