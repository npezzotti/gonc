package main

import (
	"log"
)

type Logger struct {
	*log.Logger
	cfg *Config
}

func NewLogger(l *log.Logger, cfg *Config) *Logger {
	return &Logger{
		Logger: l,
		cfg:    cfg,
	}
}

func (l *Logger) Verbose(msg string, args ...interface{}) {
	if l.cfg.Verbose {
		l.Printf(msg, args...)
	}
}

func (l *Logger) Log(msg string, args ...interface{}) {
	l.Printf(msg, args...)
}
