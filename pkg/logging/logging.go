package logging

import (
	"io"
	"os"
	"path/filepath"

	"github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"
)

// Level is the logging level
type Level logrus.Level

// Logging levels
const (
	DebugLevel Level = Level(logrus.DebugLevel)
	InfoLevel  Level = Level(logrus.InfoLevel)
	WarnLevel  Level = Level(logrus.WarnLevel)
	ErrorLevel Level = Level(logrus.ErrorLevel)
	FatalLevel Level = Level(logrus.FatalLevel)
	PanicLevel Level = Level(logrus.PanicLevel)
)

var logger = logrus.New()

func init() {
	logger.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})
	logger.SetOutput(os.Stdout)
}

// SetLevel sets the logging level
func SetLevel(level Level) {
	logger.SetLevel(logrus.Level(level))
}

// IsLevelEnabled lets callers avoid preparing diagnostics that will not be emitted.
func IsLevelEnabled(level Level) bool {
	return logger.IsLevelEnabled(logrus.Level(level))
}

// SetFormatter sets the log formatter
func SetFormatter(formatter logrus.Formatter) {
	logger.SetFormatter(formatter)
}

// SetOutput sets the log output
func SetOutput(output io.Writer) {
	logger.SetOutput(output)
}

// EnableFileLogging enables logging to a file with rotation
func EnableFileLogging(logDir, logFile string, maxSize, maxBackups, maxAge int) error {
	// Create log directory if it doesn't exist
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return err
	}

	// Configure log rotation
	logPath := filepath.Join(logDir, logFile)
	rotateLogger := &lumberjack.Logger{
		Filename:   logPath,
		MaxSize:    maxSize,    // megabytes
		MaxBackups: maxBackups, // number of backups
		MaxAge:     maxAge,     // days
		Compress:   true,       // compress backups
	}

	// Use both stdout and file for logging
	multiWriter := io.MultiWriter(os.Stdout, rotateLogger)
	logger.SetOutput(multiWriter)

	return nil
}

// WithFields creates a new log entry with fields
func WithFields(fields logrus.Fields) *logrus.Entry {
	return logger.WithFields(fields)
}

// Debugf logs a debug message
func Debugf(format string, args ...interface{}) {
	logger.Debugf(format, args...)
}

// Infof logs an info message
func Infof(format string, args ...interface{}) {
	logger.Infof(format, args...)
}

// Warnf logs a warning message
func Warnf(format string, args ...interface{}) {
	logger.Warnf(format, args...)
}

// Errorf logs an error message
func Errorf(format string, args ...interface{}) {
	logger.Errorf(format, args...)
}

// Fatalf logs a fatal message and exits
func Fatalf(format string, args ...interface{}) {
	logger.Fatalf(format, args...)
}

// DebugWithFields logs a debug message with fields
func DebugWithFields(fields logrus.Fields, format string, args ...interface{}) {
	logger.WithFields(fields).Debugf(format, args...)
}

// InfoWithFields logs an info message with fields
func InfoWithFields(fields logrus.Fields, format string, args ...interface{}) {
	logger.WithFields(fields).Infof(format, args...)
}

// WarnWithFields logs a warning message with fields
func WarnWithFields(fields logrus.Fields, format string, args ...interface{}) {
	logger.WithFields(fields).Warnf(format, args...)
}

// ErrorWithFields logs an error message with fields
func ErrorWithFields(fields logrus.Fields, format string, args ...interface{}) {
	logger.WithFields(fields).Errorf(format, args...)
}

// FatalWithFields logs a fatal message with fields and exits
func FatalWithFields(fields logrus.Fields, format string, args ...interface{}) {
	logger.WithFields(fields).Fatalf(format, args...)
}
