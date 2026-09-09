package proxy

import (
	"bytes"
	"compress/gzip"
	"io"
	"mime"
	"regexp"
	"strings"

	"github.com/JoeyLearnsToCode/codebuddy-gate/internal/session"
)

// codebuddy code 的 Web UI 使用根绝对路径（/assets/*、/api/v1/* 等），
// 网关把每个会话挂在 /<sessionId>/ 前缀下，因此必须把响应体里这些路径补上前缀，
// 否则浏览器会直接请求网关根路径而拿不到资源。
//
// 只收录「确定是根绝对路径」的前缀：像 /events 这种既可能是根路径、也可能是拼在
// /api/v1/agent-home 后面的相对后缀（IR("/events")），一律不收录，否则会拼出
// /api/v1/agent-home/<sessionId>/events 这种 404 的 URL。
var absPathRe = regexp.MustCompile(
	"([\"'`(])/(api/|assets/|internal/|loader\\.js|sandbox_proxy\\.html|manifest\\.webmanifest|logo\\.svg|pwa-icon\\.svg|sw\\.js|favicon\\.ico)")

// maxRewriteSize 超过该体积的响应体不再改写（避免大文件吃内存）。
const maxRewriteSize = 32 << 20

// rewriteBody 把响应体中的根绝对路径改写为 /<prefix>/ 下的路径。
func rewriteBody(body []byte, prefix string) []byte {
	if len(body) == 0 || len(body) > maxRewriteSize {
		return body
	}
	return absPathRe.ReplaceAll(body, []byte("${1}"+prefix+"/$2"))
}

// rewritable 判断该响应体是否需要补 /<prefix> 路径前缀。
func rewritable(contentType string) bool {
	return mediaTypeIs(contentType, "text/html", "text/css", "text/javascript",
		"application/javascript", "application/xhtml+xml", "image/svg+xml")
}

// endpointRewritable 判断该响应体里可能含有需要改写的会话 endpoint。
// 比 rewritable 多一个 application/json：Workers / 监控面板的地址是接口返回的 JSON。
func endpointRewritable(contentType string) bool {
	return mediaTypeIs(contentType, "text/html", "text/css", "text/javascript",
		"application/javascript", "application/xhtml+xml", "image/svg+xml", "application/json")
}

func mediaTypeIs(contentType string, want ...string) bool {
	base, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return false
	}
	for _, w := range want {
		if base == w {
			return true
		}
	}
	return false
}

// rewriteEndpoints 把响应体里的会话 endpoint（http://127.0.0.1:60853）
// 换成网关上的地址（http://<网关 host>/<sessionId>），
// 这样监控页 / Workers 面板上的链接点开后仍然走网关。
func rewriteEndpoints(body []byte, host string, paths []session.EndpointPath) []byte {
	for _, p := range paths {
		// 先替换带路径的形式，再替换裸 endpoint，避免重复命中。
		body = bytes.ReplaceAll(body, []byte(p.Endpoint+"/"), []byte(host+p.Path+"/"))
		body = bytes.ReplaceAll(body, []byte(p.Endpoint), []byte(host+p.Path))
	}
	return body
}

// gunzip 解压 gzip 响应体，失败时返回错误由调用方决定降级策略。
func gunzip(body []byte) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	return io.ReadAll(zr)
}

// rewriteLocation 处理上游的跳转地址：
//   - /xxx            -> /<prefix>/xxx
//   - http://ep/xxx   -> /<prefix>/xxx
//   - 其它（外站等）    -> 原样保留
func rewriteLocation(loc, endpoint, prefix string) string {
	if strings.HasPrefix(loc, "/") {
		if strings.HasPrefix(loc, "//") {
			return loc
		}
		return prefix + loc
	}
	if strings.HasPrefix(loc, strings.TrimSuffix(endpoint, "/")+"/") {
		trimmed := strings.TrimPrefix(loc, strings.TrimSuffix(endpoint, "/"))
		return prefix + trimmed
	}
	return loc
}
