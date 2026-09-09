// Package session 发现并解析 codebuddy code 的活跃会话。
//
// codebuddy code 会在 ~/.codebuddy/sessions/<pid>.json 写入一个会话描述文件，
// 其中的 endpoint 就是该会话内置 Web 服务的地址。
package session

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/JoeyLearnsToCode/codebuddy-gate/internal/logging"
)

// Info 对应 ~/.codebuddy/sessions/<pid>.json 的内容。
type Info struct {
	PID           int    `json:"pid"`
	SessionID     string `json:"sessionId"`
	CWD           string `json:"cwd"`
	StartedAt     int64  `json:"startedAt"`
	LastHeartbeat int64  `json:"lastHeartbeat"`
	Endpoint      string `json:"endpoint"`
	URL           string `json:"url"`
	Mode          string `json:"mode"`
	Kind          string `json:"kind"`
	Version       string `json:"version"`
	Hostname      string `json:"hostname"`
	UpdatedAt     int64  `json:"updatedAt"`

	// 以下字段由网关补齐，便于页面展示。
	File      string `json:"file"`      // 会话文件名
	Project   string `json:"project"`   // cwd 的最后一段目录名
	Active    bool   `json:"active"`    // 心跳是否还在活跃窗口内
	Heartbeat string `json:"heartbeat"` // 最近心跳的本地时间
	Started   string `json:"started"`   // 启动的本地时间
	Path      string `json:"path"`      // 网关上的访问前缀 /<sessionId>/
}

// EndpointPath 把一个会话 endpoint 映射到网关上的访问路径。
type EndpointPath struct {
	Endpoint string // http://127.0.0.1:50853
	Path     string // /<sessionId>
}

// Store 负责扫描会话目录。
type Store struct {
	Dir          string
	ActiveWindow time.Duration
}

// EndpointPaths 返回所有会话的 endpoint 到网关路径的映射，
// 按 endpoint 长度倒序，避免一个 endpoint 是另一个的前缀时替换出错。
func (s *Store) EndpointPaths() []EndpointPath {
	list, err := s.List()
	if err != nil {
		return nil
	}
	out := make([]EndpointPath, 0, len(list))
	for _, it := range list {
		if it.Endpoint == "" || it.SessionID == "" {
			continue
		}
		out = append(out, EndpointPath{
			Endpoint: strings.TrimSuffix(it.Endpoint, "/"),
			Path:     "/" + it.SessionID,
		})
	}
	sort.Slice(out, func(i, j int) bool { return len(out[i].Endpoint) > len(out[j].Endpoint) })
	return out
}

// List 返回目录中所有会话，按最近心跳倒序。
func (s *Store) List() ([]Info, error) {
	entries, err := os.ReadDir(s.Dir)
	if err != nil {
		return nil, err
	}
	out := make([]Info, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.EqualFold(filepath.Ext(e.Name()), ".json") {
			continue
		}
		info, err := s.load(filepath.Join(s.Dir, e.Name()))
		if err != nil {
			logging.Warn("跳过会话文件 %s: %v", e.Name(), err)
			continue
		}
		out = append(out, *info)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].PID < out[j].PID
	})
	return out, nil
}

// Lookup 按 sessionId 或 pid 查找会话；多个匹配时优先取活跃的、再取心跳最新的。
func (s *Store) Lookup(id string) *Info {
	list, err := s.List()
	if err != nil {
		return nil
	}
	var best *Info
	for i := range list {
		if !match(&list[i], id) {
			continue
		}
		if best == nil || better(&list[i], best) {
			best = &list[i]
		}
	}
	return best
}

func match(info *Info, id string) bool {
	if info.SessionID != "" && strings.EqualFold(info.SessionID, id) {
		return true
	}
	return strconv.Itoa(info.PID) == id
}

func better(a, b *Info) bool {
	if a.Active != b.Active {
		return a.Active
	}
	return a.LastHeartbeat > b.LastHeartbeat
}

func (s *Store) load(path string) (*Info, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var info Info
	if err := json.Unmarshal(raw, &info); err != nil {
		return nil, err
	}
	if info.Endpoint == "" {
		info.Endpoint = info.URL
	}
	if info.Endpoint == "" {
		return nil, errNoEndpoint
	}
	info.File = filepath.Base(path)
	info.Project = filepath.Base(info.CWD)
	info.Active = time.Since(time.UnixMilli(info.LastHeartbeat)) <= s.ActiveWindow
	info.Heartbeat = local(info.LastHeartbeat)
	info.Started = local(info.StartedAt)
	info.Path = "/" + info.SessionID + "/"
	return &info, nil
}

func local(ms int64) string {
	if ms <= 0 {
		return "-"
	}
	return time.UnixMilli(ms).Format("2006-01-02 15:04:05")
}

var errNoEndpoint = &noEndpointError{}

type noEndpointError struct{}

func (e *noEndpointError) Error() string { return "session json 缺少 endpoint" }
