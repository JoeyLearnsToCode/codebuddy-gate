// Package logging 提供按级别过滤的日志。
//
// 默认级别为 INFO：DEBUG 日志（例如每请求的访问日志）只有在显式开启 debug 后才输出。
package logging

import (
	"log"
	"os"
	"strings"
	"sync/atomic"
)

// Level 是日志级别，数值越小越详细。
type Level int32

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "DEBUG"
	case LevelInfo:
		return "INFO"
	case LevelWarn:
		return "WARN"
	case LevelError:
		return "ERROR"
	}
	return "INFO"
}

// ParseLevel 解析级别名，无法识别时返回 ok=false。
func ParseLevel(s string) (Level, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return LevelDebug, true
	case "info":
		return LevelInfo, true
	case "warn", "warning":
		return LevelWarn, true
	case "error":
		return LevelError, true
	}
	return LevelInfo, false
}

var current atomic.Int32

func init() { current.Store(int32(LevelInfo)) }

// SetLevel 调整全局输出级别。
func SetLevel(l Level) { current.Store(int32(l)) }

// Current 返回当前输出级别。
func Current() Level { return Level(current.Load()) }

var (
	std    = log.New(os.Stderr, "", log.LstdFlags)
	stdErr = log.New(os.Stderr, "", log.LstdFlags)
)

// Debug 输出调试日志。
func Debug(format string, args ...any) { output(LevelDebug, format, args...) }

// Info 输出常规日志。
func Info(format string, args ...any) { output(LevelInfo, format, args...) }

// Warn 输出警告日志。
func Warn(format string, args ...any) { output(LevelWarn, format, args...) }

// Error 输出错误日志。
func Error(format string, args ...any) { output(LevelError, format, args...) }

func output(l Level, format string, args ...any) {
	if l < Current() {
		return
	}

	levelPrefix := "[" + l.String() + "]"
	if l == LevelError {
		stdErr.Printf(levelPrefix+" "+format, args...)
	} else {
		std.Printf(levelPrefix+" "+format, args...)
	}
}
