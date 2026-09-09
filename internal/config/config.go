// Package config 解析 codebuddy-gate 的运行配置。
//
// 取值优先级：命令行参数 > 环境变量 > 内置默认值。
// 所有环境变量统一使用 EnvPrefix 前缀，例如 CBC_GATE_ADDR。
package config

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/JoeyLearnsToCode/codebuddy-gate/internal/logging"
)

// EnvPrefix 是全部环境变量的公共前缀。
const EnvPrefix = "CBC_GATE_"

// Config 是网关运行所需的全部参数。
type Config struct {
	Addr         string        // 监听地址
	SessionsDir  string        // codebuddy session json 目录
	User         string        // 登录用户名
	PassSHA256   []byte        // 登录口令的 sha256
	Secret       []byte        // 鉴权 cookie 的 HMAC 密钥
	CookieTTL    time.Duration // 鉴权 cookie 有效期
	ActiveWindow time.Duration // 心跳超过该时长视为会话已退出
	NoAuth       bool          // true 时关闭登录鉴权（仅限本机调试）
	LogLevel     logging.Level // 最低输出级别
}

// Load 解析命令行参数与环境变量，缺失项使用默认值。
func Load(args []string) (*Config, error) {
	fs := flag.NewFlagSet("codebuddy-gate", flag.ContinueOnError)
	fs.Usage = func() { usage(fs) }

	var (
		fAddr   = fs.String("addr", "", "监听地址")
		fDir    = fs.String("sessions-dir", "", "codebuddy 会话 json 目录")
		fUser   = fs.String("user", "", "登录用户名")
		fPass   = fs.String("password", "", "登录口令（明文，推荐改用 -password-sha256）")
		fPassHA = fs.String("password-sha256", "", "登录口令的 sha256 十六进制（推荐，口令不出现在命令行与进程列表里）")
		fLevel  = fs.String("log-level", "", "日志级别：debug|info|warn|error")
		fDebug  = fs.Bool("debug", false, "开启 DEBUG 日志，等价于 -log-level=debug")
		fTTL    = fs.Duration("cookie-ttl", 0, "登录有效期")
		fActive = fs.Duration("active-window", 0, "心跳超过该时长视为会话已退出")
		fNoAuth = fs.Bool("no-auth", false, "关闭登录鉴权（仅限本机调试）")
	)
	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	given := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { given[f.Name] = true })

	home, err := os.UserHomeDir()
	if err != nil {
		home = ""
	}

	secret, err := loadSecret()
	if err != nil {
		return nil, err
	}
	passSHA, err := loadPassSHA256(*fPass, given["password"], *fPassHA, given["password-sha256"])
	if err != nil {
		return nil, err
	}

	noAuth := *fNoAuth
	if !given["no-auth"] {
		noAuth = truthy(getenv("NO_AUTH", ""))
	}

	return &Config{
		Addr:         pick(*fAddr, given["addr"], "ADDR", "127.0.0.1:8787"),
		SessionsDir:  pick(*fDir, given["sessions-dir"], "SESSIONS_DIR", filepath.Join(home, ".codebuddy", "sessions")),
		User:         pick(*fUser, given["user"], "USER", "codebuddy"),
		PassSHA256:   passSHA,
		Secret:       secret,
		CookieTTL:    pickDuration(*fTTL, given["cookie-ttl"], "COOKIE_TTL", 365*24*time.Hour),
		ActiveWindow: pickDuration(*fActive, given["active-window"], "ACTIVE_WINDOW", 5*time.Minute),
		NoAuth:       noAuth,
		LogLevel:     resolveLogLevel(*fLevel, given["log-level"], *fDebug, given["debug"]),
	}, nil
}

func usage(fs *flag.FlagSet) {
	out := fs.Output()
	fmt.Fprintln(out, "codebuddy-gate 把本机多个 codebuddy code 会话聚合到一个 HTTP 入口。")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "用法:")
	fmt.Fprintln(out, "  codebuddy-gate [参数]")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "参数（同时支持环境变量，命令行优先）:")
	fs.PrintDefaults()
	fmt.Fprintln(out)
	fmt.Fprintln(out, "提示：口令推荐用 -password-sha256 传 sha256，明文口令会出现在命令行历史与进程列表里。")
	fmt.Fprintf(out, "      生成方式：printf '你的口令' | sha256sum\n")
	fmt.Fprintln(out)
	fmt.Fprintf(out, "环境变量（%s 前缀，下划线分隔）:\n", EnvPrefix)
	for _, kv := range [][2]string{
		{"ADDR", "监听地址"},
		{"SESSIONS_DIR", "会话 json 目录"},
		{"USER", "登录用户名"},
		{"PASSWORD", "登录口令（明文）"},
		{"PASSWORD_SHA256", "登录口令的 sha256 十六进制"},
		{"SECRET", "鉴权 cookie 的 HMAC 密钥"},
		{"COOKIE_TTL", "登录有效期"},
		{"ACTIVE_WINDOW", "心跳超时"},
		{"NO_AUTH", "1 时关闭鉴权"},
		{"LOG_LEVEL", "日志级别 debug|info|warn|error"},
	} {
		fmt.Fprintf(out, "  %-24s %s\n", EnvPrefix+kv[0], kv[1])
	}
}

func loadSecret() ([]byte, error) {
	if v := getenv("SECRET", ""); v != "" {
		return []byte(v), nil
	}
	// 未配置时随机生成：进程重启后旧 cookie 失效，但无需用户准备密钥。
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("生成 cookie 密钥失败: %w", err)
	}
	return buf, nil
}

// loadPassSHA256 确定登录口令的 sha256。
// 优先级：-password / -password-sha256 > CBC_GATE_PASSWORD_SHA256 > CBC_GATE_PASSWORD > 随机口令。
func loadPassSHA256(plain string, plainSet bool, hash string, hashSet bool) ([]byte, error) {
	if plainSet && hashSet {
		return nil, fmt.Errorf("-password 与 -password-sha256 只能二选一")
	}
	if hashSet {
		return decodePassSHA256(hash)
	}
	if plainSet {
		sum := sha256.Sum256([]byte(plain))
		return sum[:], nil
	}
	if v := getenv("PASSWORD_SHA256", ""); v != "" {
		return decodePassSHA256(v)
	}
	raw := getenv("PASSWORD", "")
	if raw == "" {
		raw = rand.Text()
		logging.Warn("使用随机口令 %s，建议改用 -password-sha256 或 %sPASSWORD_SHA256 设置固定口令", raw, EnvPrefix)
	}
	sum := sha256.Sum256([]byte(raw))
	return sum[:], nil
}

func decodePassSHA256(v string) ([]byte, error) {
	b, err := hex.DecodeString(strings.TrimSpace(v))
	if err != nil || len(b) != sha256.Size {
		return nil, fmt.Errorf("口令 sha256 必须是 %d 字节的十六进制串（-password-sha256 或 %sPASSWORD_SHA256）", sha256.Size, EnvPrefix)
	}
	return b, nil
}

// resolveLogLevel 的优先级：-log-level > -debug > CBC_GATE_LOG_LEVEL > info。
func resolveLogLevel(explicit string, explicitSet, debug, debugSet bool) logging.Level {
	if explicitSet {
		if l, ok := logging.ParseLevel(explicit); ok {
			return l
		}
		logging.Warn("无法识别的日志级别 %q，使用 info", explicit)
		return logging.LevelInfo
	}
	if debugSet && debug {
		return logging.LevelDebug
	}
	if v := getenv("LOG_LEVEL", ""); v != "" {
		if l, ok := logging.ParseLevel(v); ok {
			return l
		}
		logging.Warn("%sLOG_LEVEL=%q 无法识别，使用 info", EnvPrefix, v)
	}
	return logging.LevelInfo
}

// pick 在命令行未显式给出时回落到环境变量，再回落到默认值。
func pick(flagVal string, flagSet bool, key, def string) string {
	if flagSet {
		return flagVal
	}
	return getenv(key, def)
}

func pickDuration(flagVal time.Duration, flagSet bool, key string, def time.Duration) time.Duration {
	if flagSet {
		return flagVal
	}
	return duration(key, def)
}

// getenv 读取带 EnvPrefix 前缀的环境变量。
func getenv(key, def string) string {
	if v := os.Getenv(EnvPrefix + key); v != "" {
		return v
	}
	return def
}

func duration(key string, def time.Duration) time.Duration {
	v := getenv(key, "")
	if v == "" {
		return def
	}
	if n, err := strconv.Atoi(v); err == nil {
		return time.Duration(n) * time.Second
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		logging.Warn("%s%s 无法解析(%q)，使用默认值 %s", EnvPrefix, key, v, def)
		return def
	}
	return d
}

func truthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}
