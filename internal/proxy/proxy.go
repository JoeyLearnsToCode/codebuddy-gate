// Package proxy 把请求透明转发到某个 codebuddy code 会话的 endpoint。
//
// 路由规则：
//   - /<sessionId 或 pid>/<任意路径>  -> 剥离前缀后转发，/foobar 原样保留（含 query）
//   - /assets/*、/api/* 等根绝对路径   -> 用亲和 cookie 兜底转发（前端 JS 用绝对路径发请求）
package proxy

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/JoeyLearnsToCode/codebuddy-gate/internal/session"
)

// AffinityCookie 记录浏览器最近访问的会话，用于根绝对路径的兜底转发。
const AffinityCookie = "cbg_session"

// Handler 是会话代理。
type Handler struct {
	Store   *session.Store
	Missing http.Handler // 找不到会话时的兜底页面
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	info, sub := h.resolve(r)
	if info == nil {
		h.missing().ServeHTTP(w, r)
		return
	}
	h.serve(w, r, info, sub)
}

func (h *Handler) missing() http.Handler {
	if h.Missing != nil {
		return h.Missing
	}
	return http.HandlerFunc(http.NotFound)
}

// resolve 决定请求属于哪个会话，以及要转发给上游的路径。
func (h *Handler) resolve(r *http.Request) (*session.Info, string) {
	head, rest := split(r.URL.Path)
	if head != "" {
		if info := h.Store.Lookup(head); info != nil {
			return info, rest
		}
	}
	if c, err := r.Cookie(AffinityCookie); err == nil {
		if info := h.Store.Lookup(c.Value); info != nil {
			return info, r.URL.Path
		}
	}
	return nil, ""
}

func (h *Handler) serve(w http.ResponseWriter, r *http.Request, info *session.Info, sub string) {
	endpoint, err := url.Parse(info.Endpoint)
	if err != nil || endpoint.Host == "" {
		http.Error(w, "会话 endpoint 无效: "+info.Endpoint, http.StatusBadGateway)
		return
	}
	if sub == "" {
		sub = "/"
	}

	prefix := "/" + info.SessionID
	target := singleJoin(endpoint.Path, sub)
	setAffinity(w, info)
	// 监控页 / Workers 面板上会展示各会话的 endpoint，需要换成网关自己的地址。
	gateHost := publicOrigin(r)

	rp := &httputil.ReverseProxy{
		Director: func(out *http.Request) {
			out.URL.Scheme = endpoint.Scheme
			out.URL.Host = endpoint.Host
			out.URL.Path = target
			out.URL.RawQuery = r.URL.RawQuery // query 原样透传（hash 浏览器不会发送）
			out.URL.Fragment = r.URL.Fragment
			out.Host = endpoint.Host
			out.Header.Set("X-Forwarded-Host", r.Host)
			out.Header.Set("X-Forwarded-Proto", scheme(r))
			out.Header.Set("X-Gate-Session", info.SessionID)
			// 上游会校验 Origin 白名单，只有它自己的 origin 才放行；
			// 对浏览器来说网关就是来源站点，所以换成上游 origin。
			if out.Header.Get("Origin") != "" {
				out.Header.Set("Origin", endpoint.Scheme+"://"+endpoint.Host)
			}
			// 只索取 gzip，保证响应体改写时拿到的要么是可解压的 gzip，要么是明文。
			out.Header.Set("Accept-Encoding", "gzip")
		},
		ModifyResponse: func(resp *http.Response) error {
			if resp.StatusCode < 200 || resp.StatusCode == http.StatusSwitchingProtocols {
				return nil // 1xx / 101 升级响应不能读 body
			}
			if loc := resp.Header.Get("Location"); loc != "" {
				resp.Header.Set("Location", rewriteLocation(loc, info.Endpoint, prefix))
			}
			ct := resp.Header.Get("Content-Type")
			needPath := rewritable(ct)
			needEndpoint := endpointRewritable(ct)
			if !needPath && !needEndpoint {
				return nil
			}
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				return err
			}
			if strings.EqualFold(resp.Header.Get("Content-Encoding"), "gzip") {
				plain, err := gunzip(body)
				if err != nil {
					return nil // 解压不了就原样透传
				}
				body = plain
				resp.Header.Del("Content-Encoding")
			}
			if needPath {
				body = rewriteBody(body, prefix)
			}
			if needEndpoint {
				body = rewriteEndpoints(body, gateHost, h.Store.EndpointPaths())
			}
			resp.Body = io.NopCloser(bytes.NewReader(body))
			resp.ContentLength = int64(len(body))
			resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			http.Error(w, "无法连接会话 "+info.SessionID+" ("+info.Endpoint+")："+err.Error()+
				"\n会话可能已退出，请回到 /list 查看。", http.StatusBadGateway)
		},
		FlushInterval: 200 * time.Millisecond, // 保证 SSE / 流式响应及时下发
	}
	rp.ServeHTTP(w, r)
}

func setAffinity(w http.ResponseWriter, info *session.Info) {
	http.SetCookie(w, &http.Cookie{
		Name:     AffinityCookie,
		Value:    info.SessionID,
		Path:     "/",
		MaxAge:   30 * 24 * 3600,
		SameSite: http.SameSiteLaxMode,
	})
}

// split 把 /a/b/c 拆成 ("a", "/b/c")。
func split(p string) (head, rest string) {
	p = strings.TrimPrefix(p, "/")
	i := strings.Index(p, "/")
	if i < 0 {
		return p, ""
	}
	return p[:i], p[i:]
}

func singleJoin(base, sub string) string {
	base = strings.TrimSuffix(base, "/")
	return base + sub
}

func scheme(r *http.Request) string {
	if v := r.Header.Get("X-Forwarded-Proto"); v != "" {
		return v
	}
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

// publicOrigin 返回浏览器访问网关时用的 origin，用于把 endpoint 换成网关地址。
func publicOrigin(r *http.Request) string {
	host := r.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = r.Host
	}
	return scheme(r) + "://" + host
}
