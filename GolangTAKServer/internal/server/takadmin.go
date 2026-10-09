package server

import "net/http"

func (s *Server) takAdminRoutes(m, a func(string, http.HandlerFunc)) {
	m("GET /Marti/api/inputs/storeForwardChat/enabled", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, s.envelope("java.lang.Boolean", s.Config().Retention.ChatDays > 0))
	})
	a("PUT /Marti/api/inputs/storeForwardChat/enable", func(w http.ResponseWriter, r *http.Request) { s.setStoreForward(w, true) })
	a("PUT /Marti/api/inputs/storeForwardChat/disable", func(w http.ResponseWriter, r *http.Request) { s.setStoreForward(w, false) })
}

func (s *Server) setStoreForward(w http.ResponseWriter, on bool) {
	cfg, err := s.UpdateConfig(func(c *Config) error {
		switch {
		case on && c.Retention.ChatDays <= 0:
			c.Retention.ChatDays = DefaultConfig().Retention.ChatDays
		case !on:
			c.Retention.ChatDays = 0
		}
		return nil
	})
	if err != nil {
		apiError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, s.envelope("java.lang.Boolean", cfg.Retention.ChatDays > 0))
}
