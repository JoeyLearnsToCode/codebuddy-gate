package web

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// AuthCookie 是登录态 cookie 名。
const AuthCookie = "cbg_auth"

// Auth 负责登录态的签发与校验。
type Auth struct {
	User       string
	PassSHA256 []byte
	Secret     []byte
	TTL        time.Duration
	Disabled   bool
}

// Authenticated 判断请求是否已登录。
func (a *Auth) Authenticated(r *http.Request) bool {
	if a.Disabled {
		return true
	}
	c, err := r.Cookie(AuthCookie)
	if err != nil {
		return false
	}
	user, exp, err := a.parse(c.Value)
	if err != nil {
		return false
	}
	return user == a.User && time.Now().Before(exp)
}

// Check 是 nginx auth_request 的配套端点：200 放行，401 拒绝。
func (a *Auth) Check(w http.ResponseWriter, r *http.Request) {
	if a.Authenticated(r) {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.WriteHeader(http.StatusUnauthorized)
}

// Require 给需要登录的路由加保护。
func (a *Auth) Require(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.Authenticated(r) {
			next.ServeHTTP(w, r)
			return
		}
		// 接口类请求直接 401，避免把登录页当成 JSON 返回给前端。
		if r.Method != http.MethodGet || strings.Contains(r.URL.Path, "/api/") {
			http.Error(w, "未登录", http.StatusUnauthorized)
			return
		}
		http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
	})
}

// Login 签发登录态。
func (a *Auth) Login(w http.ResponseWriter, user string) {
	exp := time.Now().Add(a.TTL)
	http.SetCookie(w, &http.Cookie{
		Name:     AuthCookie,
		Value:    a.token(user, exp),
		Path:     "/",
		MaxAge:   int(a.TTL.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// Logout 清除登录态。
func (a *Auth) Logout(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     AuthCookie,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// Verify 校验用户名与口令。
func (a *Auth) Verify(user, pass string) bool {
	sum := sha256.Sum256([]byte(pass))
	okUser := subtle.ConstantTimeCompare([]byte(user), []byte(a.User)) == 1
	okPass := subtle.ConstantTimeCompare(sum[:], a.PassSHA256) == 1
	return okUser && okPass
}

func (a *Auth) token(user string, exp time.Time) string {
	payload := user + "|" + strconv.FormatInt(exp.Unix(), 10)
	mac := hmac.New(sha256.New, a.Secret)
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." +
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (a *Auth) parse(v string) (user string, exp time.Time, err error) {
	raw, sig, ok := strings.Cut(v, ".")
	if !ok {
		return "", time.Time{}, fmt.Errorf("cookie 格式错误")
	}
	payload, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return "", time.Time{}, err
	}
	u, ts, ok := strings.Cut(string(payload), "|")
	if !ok {
		return "", time.Time{}, fmt.Errorf("cookie 内容错误")
	}
	mac := hmac.New(sha256.New, a.Secret)
	mac.Write([]byte(string(payload)))
	want := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(sig), []byte(want)) != 1 {
		return "", time.Time{}, fmt.Errorf("cookie 签名不匹配")
	}
	sec, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return "", time.Time{}, err
	}
	return u, time.Unix(sec, 0), nil
}

// landing 是登录成功（或登录态仍有效）时要去的目标地址。
// 永远不会指向 /login，否则已登录时访问 /login 会自己跳自己。
func landing(next string) string {
	target := safeNext(next)
	if target == "/login" || strings.HasPrefix(target, "/login?") {
		return "/list"
	}
	return target
}

// safeNext 只接受站内相对地址，防止开放重定向。
func safeNext(next string) string {
	if next == "" {
		return "/list"
	}
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.HasPrefix(next, "/\\") {
		return "/list"
	}
	return next
}
