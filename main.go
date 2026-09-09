package main

import (
	"context"
	"errors"
	"flag"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/JoeyLearnsToCode/codebuddy-gate/internal/config"
	"github.com/JoeyLearnsToCode/codebuddy-gate/internal/logging"
	"github.com/JoeyLearnsToCode/codebuddy-gate/internal/proxy"
	"github.com/JoeyLearnsToCode/codebuddy-gate/internal/session"
	"github.com/JoeyLearnsToCode/codebuddy-gate/internal/web"
)

func main() {
	cfg, err := config.Load(os.Args[1:])
	if errors.Is(err, flag.ErrHelp) { // -h 已经打印过用法
		return
	}
	if err != nil {
		logging.Error("配置加载失败: %v", err)
		os.Exit(1)
	}
	logging.SetLevel(cfg.LogLevel)

	store := &session.Store{Dir: cfg.SessionsDir, ActiveWindow: cfg.ActiveWindow}
	auth := &web.Auth{
		User:       cfg.User,
		PassSHA256: cfg.PassSHA256,
		Secret:     cfg.Secret,
		TTL:        cfg.CookieTTL,
		Disabled:   cfg.NoAuth,
	}
	gw := &web.Server{Auth: auth, Store: store}
	sessions := &proxy.Handler{Store: store, Missing: http.HandlerFunc(gw.NotFound)}

	mux := http.NewServeMux()
	mux.HandleFunc("/{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/list", http.StatusFound)
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/login", gw.Login)
	mux.HandleFunc("/logout", gw.Logout)
	mux.HandleFunc("/auth", auth.Check)
	mux.Handle("/_gate/api/sessions", auth.Require(http.HandlerFunc(gw.Sessions)))
	mux.Handle("/list", auth.Require(http.HandlerFunc(gw.List)))
	mux.Handle("/", auth.Require(sessions))

	srv := &http.Server{Addr: cfg.Addr, Handler: logRequests(mux)}
	go func() {
		logging.Info("监听 %s，用户 %s，日志级别 %s", cfg.Addr, cfg.User, cfg.LogLevel)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logging.Error("服务异常退出: %v", err)
			os.Exit(1)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		logging.Warn("关闭超时: %v", err)
	}
}

// logRequests 输出每请求的访问日志（DEBUG 级别，默认不打印）。
func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, code: http.StatusOK}
		start := time.Now()
		next.ServeHTTP(rec, r)
		logging.Debug("%s %s -> %d (%s)", r.Method, r.URL.RequestURI(), rec.code, time.Since(start).Round(time.Millisecond))
	})
}

type statusRecorder struct {
	http.ResponseWriter
	code int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.code = code
	s.ResponseWriter.WriteHeader(code)
}

// Unwrap 让 http.ResponseController 能拿到底层 ResponseWriter，
// 否则 WebSocket 升级（Hijack）和流式 Flush 会被这层包装挡住。
func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }
