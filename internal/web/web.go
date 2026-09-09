// Package web 提供网关自身的页面：登录、会话列表、nginx auth_request 端点。
package web

import (
	"embed"
	"encoding/json"
	"html/template"
	"net/http"

	"github.com/JoeyLearnsToCode/codebuddy-gate/internal/session"
)

//go:embed templates/*.html
var templatesFS embed.FS

var templates = template.Must(template.New("").ParseFS(templatesFS, "templates/*.html"))

// Server 聚合网关自身的 HTTP 处理。
type Server struct {
	Auth  *Auth
	Store *session.Store
}

// Login 展示/提交登录表单。
func (s *Server) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		// 登录态还有效就没必要再看登录页，直接去目标页面。
		if s.Auth.Authenticated(r) {
			http.Redirect(w, r, landing(r.URL.Query().Get("next")), http.StatusFound)
			return
		}
		s.render(w, "login.html", map[string]any{
			"Next": r.URL.Query().Get("next"),
		})
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "表单解析失败", http.StatusBadRequest)
		return
	}
	next := landing(r.PostFormValue("next"))
	user := r.PostFormValue("user")
	if !s.Auth.Verify(user, r.PostFormValue("pass")) {
		w.WriteHeader(http.StatusUnauthorized)
		s.render(w, "login.html", map[string]any{
			"Next":  next,
			"Error": "用户名或密码错误",
		})
		return
	}
	s.Auth.Login(w, user)
	http.Redirect(w, r, next, http.StatusFound)
}

// Logout 清除登录态后回到登录页。
func (s *Server) Logout(w http.ResponseWriter, r *http.Request) {
	s.Auth.Logout(w)
	http.Redirect(w, r, "/login", http.StatusFound)
}

// List 是会话列表页。
func (s *Server) List(w http.ResponseWriter, r *http.Request) {
	all := r.URL.Query().Get("all") == "1"
	list, err := s.Store.List()
	if err != nil {
		s.errorPage(w, http.StatusInternalServerError, "读取会话目录失败", err.Error())
		return
	}
	if !all {
		list = active(list)
	}
	s.render(w, "list.html", map[string]any{
		"Sessions": list,
		"Dir":      s.Store.Dir,
		"ShowAll":  all,
	})
}

// Sessions 返回会话列表 JSON，供列表页轮询。
func (s *Server) Sessions(w http.ResponseWriter, r *http.Request) {
	list, err := s.Store.List()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if r.URL.Query().Get("all") != "1" {
		list = active(list)
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(list)
}

// NotFound 是代理找不到会话时的兜底页面。
func (s *Server) NotFound(w http.ResponseWriter, r *http.Request) {
	s.errorPage(w, http.StatusNotFound,
		"没有匹配的 codebuddy code 会话",
		"请在 /list 中选择一个会话后再访问，或确认会话仍在运行。")
}

func (s *Server) errorPage(w http.ResponseWriter, code int, title, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	s.render(w, "error.html", map[string]any{
		"Title":   title,
		"Message": msg,
	})
}

func (s *Server) render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := templates.ExecuteTemplate(w, name, data); err != nil {
		http.Error(w, "渲染页面失败: "+err.Error(), http.StatusInternalServerError)
	}
}

func active(list []session.Info) []session.Info {
	out := make([]session.Info, 0, len(list))
	for _, it := range list {
		if it.Active {
			out = append(out, it)
		}
	}
	return out
}
