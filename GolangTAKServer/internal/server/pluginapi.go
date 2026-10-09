package server

import (
	"net/http"
	"strings"
)

func (s *Server) martiPluginInfo(w http.ResponseWriter, r *http.Request) {
	out := []map[string]any{}
	if s.plugins != nil {
		for _, st := range s.plugins.status() {
			out = append(out, map[string]any{
				"name": st.Name, "description": st.Description, "className": st.Name, "version": st.Version, "tag": "",
				"enabled": st.Enabled, "started": st.State == "running", "exceptionMessage": st.LastExit, "archiveEnabled": false,
			})
		}
	}
	writeJSON(w, http.StatusOK, s.envelope("PluginInfo", out))
}

func (s *Server) martiPluginToggle(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	on := strings.EqualFold(q.Get("status"), "true")
	name := q.Get("name")
	found := false
	s.UpdateConfig(func(c *Config) error {
		for i := range c.Plugins {
			if name == "" || strings.EqualFold(c.Plugins[i].Name, name) {
				c.Plugins[i].Enabled = on
				found = true
			}
		}
		return nil
	})
	if !found && name != "" {
		writeJSON(w, http.StatusNotFound, s.envelope("java.lang.Boolean", false))
		return
	}
	if s.plugins != nil {
		s.plugins.reload(s.Config().Plugins)
	}
	writeJSON(w, http.StatusOK, s.envelope("java.lang.Boolean", true))
}

func (s *Server) martiPluginSubmit(w http.ResponseWriter, r *http.Request) {
	rest := "submit"
	if strings.HasSuffix(r.URL.Path, "/submit/result") {
		rest = "submit/result"
	}
	r.SetPathValue("rest", rest)
	s.pluginProxy(w, r)
}
