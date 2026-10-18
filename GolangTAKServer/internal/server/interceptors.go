package server

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/cot"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/websocket"
)

type interceptVerdict struct {
	ID     uint64 `json:"id"`
	Action string `json:"action"`
	XML    string `json:"xml,omitempty"`
}

type interceptor struct {
	name    string
	types   []string
	timeout time.Duration
	conn    *websocket.Conn
	wmu     sync.Mutex
	pmu     sync.Mutex
	pending map[uint64]chan interceptVerdict
	next    atomic.Uint64
	dead    atomic.Bool
}

type interceptorSet struct {
	mu   sync.RWMutex
	list []*interceptor
}

func (is *interceptorSet) add(i *interceptor) {
	is.mu.Lock()
	is.list = append(is.list, i)
	is.mu.Unlock()
}

func (is *interceptorSet) remove(i *interceptor) {
	is.mu.Lock()
	for n, x := range is.list {
		if x == i {
			is.list = append(is.list[:n:n], is.list[n+1:]...)
			break
		}
	}
	is.mu.Unlock()
}

func (is *interceptorSet) active() []*interceptor {
	is.mu.RLock()
	defer is.mu.RUnlock()
	return is.list
}

func (i *interceptor) call(m *Message) (interceptVerdict, bool) {
	id := i.next.Add(1)
	ch := make(chan interceptVerdict, 1)
	i.pmu.Lock()
	i.pending[id] = ch
	i.pmu.Unlock()
	defer func() {
		i.pmu.Lock()
		delete(i.pending, id)
		i.pmu.Unlock()
	}()
	src := ""
	if m.Source != nil {
		src = m.Source.UID()
	}
	payload, _ := json.Marshal(map[string]any{"id": id, "xml": string(m.Event.XML()), "type": m.Event.Type, "uid": m.Event.UID, "source": src})
	i.wmu.Lock()
	i.conn.SetWriteDeadline(time.Now().Add(i.timeout))
	err := i.conn.WriteText(string(payload))
	i.wmu.Unlock()
	if err != nil {
		i.dead.Store(true)
		return interceptVerdict{}, false
	}
	select {
	case v := <-ch:
		return v, true
	case <-time.After(i.timeout):
		return interceptVerdict{}, false
	}
}

func (s *Server) runInterceptors(m *Message) bool {
	list := s.intercept.active()
	if len(list) == 0 || m.Event == nil || m.Event.IsControl() || (m.Source != nil && m.Source.Kind == KindCluster) {
		return true
	}
	for _, i := range list {
		if i.dead.Load() || (len(i.types) > 0 && !typeMatches(m.Event.Type, i.types)) {
			continue
		}
		v, ok := i.call(m)
		if !ok {
			continue
		}
		switch strings.ToLower(v.Action) {
		case "drop":
			return false
		case "replace":
			e, err := cot.Parse([]byte(v.XML))
			if err != nil {
				s.log.Warn("interceptor returned invalid CoT; keeping the original", "plugin", i.name, "err", err)
				continue
			}
			m.Event = e
		}
	}
	return true
}

func (s *Server) apiPluginIntercept(w http.ResponseWriter, r *http.Request) {
	id := identityOf(r)
	if id == nil || (!id.Admin && !strings.HasPrefix(id.Name, "plugin-")) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "only server plugins and administrators can intercept messages"})
		return
	}
	q := r.URL.Query()
	timeout := 250 * time.Millisecond
	if n, err := strconv.Atoi(q.Get("timeoutMs")); err == nil && n > 0 && n <= 5000 {
		timeout = time.Duration(n) * time.Millisecond
	}
	conn, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	defer conn.CloseNow()
	i := &interceptor{name: id.Name, types: splitList(q.Get("types")), timeout: timeout, conn: conn, pending: map[uint64]chan interceptVerdict{}}
	s.intercept.add(i)
	defer s.intercept.remove(i)
	s.log.Info("message interceptor attached", "plugin", id.Name, "types", q.Get("types"))
	for {
		_, data, err := conn.ReadMessage()
		if err != nil {
			s.log.Info("message interceptor detached", "plugin", id.Name)
			return
		}
		var v interceptVerdict
		if json.Unmarshal(data, &v) != nil {
			continue
		}
		i.pmu.Lock()
		ch := i.pending[v.ID]
		i.pmu.Unlock()
		if ch != nil {
			select {
			case ch <- v:
			default:
			}
		}
	}
}
