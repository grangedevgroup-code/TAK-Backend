package server

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/web"
)

func (s *Server) routes() *http.ServeMux {
	mux := http.NewServeMux()
	m := func(p string, h http.HandlerFunc) { mux.HandleFunc(p, s.guard(accessMarti, h)) }
	u := func(p string, h http.HandlerFunc) { mux.HandleFunc(p, s.guard(accessUser, h)) }
	a := func(p string, h http.HandlerFunc) { mux.HandleFunc(p, s.guard(accessAdmin, h)) }
	pub := func(p string, h http.HandlerFunc) { mux.HandleFunc(p, h) }

	pub("GET /metrics", s.metricsHandler)
	pub("GET /api/cluster/ws", s.apiClusterSocket)
	pub("GET /api/cluster/blob/{hash}", s.apiClusterBlob)
	pub("GET /Marti/api/version", s.martiVersion)
	pub("GET /Marti/api/version/config", s.martiVersionConfig)
	pub("GET /Marti/api/version/info", s.martiVersionInfo)
	pub("GET /Marti/api/node/id", s.martiNodeID)
	pub("GET /Marti/api/security/isSecure", s.martiIsSecure)
	m("GET /Marti/api/util/user/roles", s.martiUserRoles)
	m("GET /Marti/api/util/isAdmin", s.martiIsAdmin)
	m("GET /Marti/api/clientEndPoints", s.martiClientEndpoints)
	m("GET /Marti/api/contacts/all", s.martiContacts)
	m("GET /Marti/api/contacts/all/full", s.martiContacts)
	m("GET /Marti/api/contacts/all/lite", s.martiContacts)
	m("GET /Marti/api/groups/all", s.martiGroupsAll)
	m("GET /Marti/api/groups", s.martiGroupsAll)
	m("GET /Marti/api/groups/groupCacheEnabled", s.martiGroupCache)
	m("PUT /Marti/api/groups/active", s.martiGroupsActive)
	m("PUT /Marti/api/groups/activebits", s.martiOK)
	m("GET /Marti/api/groups/activeForce", s.martiGroupsUpdate)
	m("GET /Marti/api/groups/update/{user}", s.martiGroupsUpdate)
	m("GET /Marti/api/groups/user", s.martiGroupsAll)
	m("GET /Marti/api/groups/{name}/{direction}", s.martiGroup)
	m("GET /Marti/api/groupprefix", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, s.envelope("java.lang.String", ""))
	})
	m("GET /Marti/api/subscriptions/all", s.martiSubscriptions)
	m("GET /Marti/api/cot/xml/{uid}", s.martiCotXML)
	m("GET /Marti/api/cot/xml/{uid}/all", s.martiCotXMLAll)
	m("GET /Marti/api/cot/sa", s.martiCotSA)
	m("GET /Marti/api/cot", s.martiCotSA)
	m("GET /Marti/api/plugins/info/all", s.martiPluginInfo)
	m("GET /Marti/api/plugins/info/all/started", s.martiPluginInfo)
	m("GET /Marti/api/plugins/info/started", s.martiPluginInfo)
	m("GET /Marti/api/plugins/info/enabled", s.martiPluginInfo)
	a("POST /Marti/api/plugins/info/all/started", s.martiPluginToggle)
	a("POST /Marti/api/plugins/info/started", s.martiPluginToggle)
	a("POST /Marti/api/plugins/info/enabled", s.martiPluginToggle)
	a("POST /Marti/api/plugins/info/archive", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, s.envelope("java.lang.Boolean", true))
	})
	mux.HandleFunc("/Marti/api/plugins/{name}/submit", s.martiPluginSubmit)
	mux.HandleFunc("PUT /Marti/api/plugins/{name}/submit/result", s.martiPluginSubmit)
	m("GET /Marti/api/maplayers/all", s.martiMapLayersAll)
	m("GET /Marti/api/maplayers/{uid}", s.martiMapLayerGet)
	m("POST /Marti/api/maplayers", s.martiMapLayerSave)
	m("PUT /Marti/api/maplayers", s.martiMapLayerSave)
	m("DELETE /Marti/api/maplayers/{uid}", s.martiMapLayerDelete)
	m("GET /Marti/api/certadmin/cert", s.martiCertAdmin)
	m("GET /Marti/api/certadmin/cert/{a}", s.martiCertAdmin)
	m("GET /Marti/api/certadmin/cert/{a}/{b}", s.martiCertAdmin)
	m("DELETE /Marti/api/certadmin/cert/{a}", s.martiCertAdmin)
	m("DELETE /Marti/api/certadmin/cert/{a}/{b}", s.martiCertAdmin)
	m("GET /Marti/api/injectors/cot/uid", s.martiInjectors)
	m("GET /Marti/api/injectors/cot/uid/{uid}", s.martiInjectors)
	m("POST /Marti/api/injectors/cot/uid", s.martiInjectors)
	m("PUT /Marti/api/injectors/cot/uid", s.martiInjectors)
	m("DELETE /Marti/api/injectors/cot/uid", s.martiInjectors)
	m("DELETE /Marti/api/injectors/cot/uid/{uid}", s.martiInjectors)
	m("GET /Marti/api/files/metadata/count", s.filesCount)
	m("GET /files/api/config", s.filesConfig)
	m("GET /Marti/sync/{hash}/metadata", s.syncMetadata)
	m("POST /Marti/ExportMissionKML", s.martiExportKML)
	m("GET /Marti/api/repeater/list", s.martiRepeaterList)
	m("GET /Marti/api/repeater/period", s.martiRepeaterPeriod)
	m("POST /Marti/api/repeater/period", s.martiRepeaterPeriod)
	m("GET /Marti/api/repeater/remove/{uid}", s.martiRepeaterRemove)
	m("GET /Marti/api/security/config", s.martiSecurityConfig)
	m("GET /Marti/api/authentication/config", s.martiAuthConfig)
	m("GET /Marti/api/security/verifyConfig", s.martiVerifyConfig)
	m("GET /Marti/api/pagedmissions", s.martiPagedMissions)
	m("GET /Marti/api/user-management/api/{action}", s.martiUserManagement)
	m("POST /Marti/api/user-management/api/{action}", s.martiUserManagement)
	m("PUT /Marti/api/user-management/api/{action}", s.martiUserManagement)
	m("GET /Marti/api/user-management/api/{action}/{arg}", s.martiUserManagement)
	m("DELETE /Marti/api/user-management/api/{action}/{arg}", s.martiUserManagement)
	m("PUT /Marti/api/video/{uid}", s.videoPut)
	m("GET /Marti/api/datafeeds", s.martiDataFeeds)
	m("GET /Marti/api/datafeeds/stats", s.martiDataFeedStats)
	m("GET /Marti/api/datafeeds/stats/{uuid}", s.martiDataFeedStats)
	m("GET /Marti/api/datafeeds/bounds/{bbox}", s.martiDataFeedsInBounds)
	m("GET /Marti/api/datafeeds/{uuid}/{what}", func(w http.ResponseWriter, r *http.Request) {
		if r.PathValue("what") != "cots_types" {
			s.martiUnknown(w, r)
			return
		}
		s.martiDataFeedTypes(w, r)
	})
	m("GET /Marti/api/datafeeds/{uuid}/cots/{type}", s.martiDataFeedCots)
	m("GET /Marti/api/iconset/all/uid", s.martiEmpty("java.lang.String"))

	pub("GET /Marti/api/tls/config", s.martiTLSConfig)
	u("POST /Marti/api/tls/signClient", s.martiSignClientV1)
	u("POST /Marti/api/tls/signClient/{$}", s.martiSignClientV1)
	u("POST /Marti/api/tls/signClient/v2", s.martiSignClientV2)
	u("GET /Marti/api/tls/makeClientKeyStore", s.martiMakeKeyStore)
	m("GET /Marti/api/tls/profile/enrollment", s.martiEnrollmentProfile)
	m("GET /Marti/api/device/profile/connection", s.martiConnectionProfile)
	m("GET /Marti/api/device/profile/tool/{tool}", s.martiToolProfile)
	m("GET /api/connection", s.martiConnectionProfile)

	m("POST /Marti/sync/missionupload", s.martiMissionUpload)
	m("PUT /Marti/sync/missionupload", s.martiMissionUpload)
	m("GET /Marti/sync/missionquery", s.martiMissionQuery)
	m("POST /Marti/sync/upload", s.martiSyncUpload)
	m("PUT /Marti/sync/upload", s.martiSyncUpload)
	m("GET /Marti/sync/content", s.martiSyncContent)
	m("HEAD /Marti/sync/content", s.martiSyncContent)
	m("PUT /Marti/sync/content", s.martiSyncContentPut)
	m("POST /Marti/sync/content", s.martiSyncContentPut)
	m("GET /Marti/sync/search", s.martiSyncSearch)
	m("DELETE /Marti/sync/delete", s.martiFileDelete)
	m("GET /Marti/api/sync/search", s.martiAPISyncSearch)
	m("GET /Marti/api/sync/metadata/{hash}/tool", s.martiMetadataTool)
	m("PUT /Marti/api/sync/metadata/{hash}/tool", s.martiMetadataTool)
	m("PUT /Marti/api/sync/metadata/{hash}/keywords", s.martiMetadataKeywords)
	m("PUT /Marti/api/sync/metadata/{hash}/expiration", s.martiMetadataExpiration)
	m("GET /Marti/api/files/metadata", s.martiFilesMetadata)
	m("GET /Marti/api/files/{hash}", s.martiFileGet)
	m("DELETE /Marti/api/files/{hash}", s.martiFileDelete)

	mux.HandleFunc("/Marti/api/missions", s.guard(accessMarti, s.missionRouter))
	mux.HandleFunc("/Marti/api/missions/", s.guard(accessMarti, s.missionRouter))

	m("GET /Marti/vcm", s.vcmGet)
	m("POST /Marti/vcm", s.vcmPost)
	m("GET /Marti/api/video", s.videoList)
	m("POST /Marti/api/video", s.videoPost)
	m("GET /Marti/api/video/{uid}", s.videoGet)
	m("DELETE /Marti/api/video/{uid}", s.videoDelete)

	m("GET /Marti/ExportMissionKML", s.martiExportKML)
	m("GET /Marti/TracksKML", s.martiExportKML)

	s.excheckRoutes(m)
	s.citrapRoutes(m)
	s.takAdminRoutes(m, a)

	pub("GET /api/packages", s.packagesList)
	pub("GET /api/packages/product.infz", s.packagesProductInfz)
	pub("HEAD /api/packages/product.infz", s.packagesProductInfz)
	pub("GET /api/packages/product.inf", s.packagesProductInf)
	pub("GET /api/packages/repositories.inf", s.packagesRepositories)
	pub("GET /api/packages/{file}", s.packagesFile)
	pub("GET /api/packages/{atak}/product.infz", s.packagesProductInfz)
	pub("HEAD /api/packages/{atak}/product.infz", s.packagesProductInfz)
	pub("GET /api/packages/{atak}/product.inf", s.packagesProductInf)
	pub("GET /api/packages/{atak}/{file}", s.packagesFile)

	pub("POST /api/login", s.apiLogin)
	pub("POST /oauth/token", s.oauthToken)
	pub("GET /.well-known/acme-challenge/{token}", s.acmeChallenge)
	a("GET /api/letsencrypt", s.apiACME)
	a("GET /api/telegram", s.apiTelegram)
	a("GET /api/jobs", s.apiJobs)
	a("POST /api/jobs/{id}/{action}", s.apiJobAction)
	a("POST /api/telegram", s.apiTelegram)
	a("POST /api/letsencrypt", s.apiACME)
	pub("POST /api/login/verify", s.apiLoginVerify)
	pub("GET /api/auth/options", s.apiAuthOptions)
	pub("POST /api/password/forgot", s.apiPasswordForgot)
	pub("POST /api/password/reset", s.apiPasswordReset)
	pub("POST /api/register", s.apiRegister)
	pub("POST /api/register/verify", s.apiRegisterVerify)
	u("GET /api/account", s.apiAccount)
	u("PUT /api/account/email", s.apiAccountEmail)
	u("POST /api/account/2fa/totp", s.apiTOTPSetup)
	u("POST /api/account/2fa/enable", s.apiTwoFactorEnable)
	u("DELETE /api/account/2fa", s.apiTwoFactorDisable)
	a("DELETE /api/users/{name}/2fa", s.apiUserReset2FA)
	a("POST /api/users/{name}/approve", s.apiUserApprove)
	a("POST /api/settings/email/test", s.apiEmailTest)
	pub("GET /locate", s.locatePage)
	pub("POST /locate/api", s.locatePost)
	pub("POST /api/logout", s.apiLogout)
	pub("GET /api/ca.pem", s.apiCA)
	pub("GET /api/truststore.p12", s.apiTrustStore)
	pub("GET /dl/{token}", s.downloadByLink)
	u("GET /api/me", s.apiMe)
	u("PUT /api/me/password", s.apiMePassword)
	u("GET /api/status", s.apiStatus)
	u("GET /api/connect", s.apiConnect)
	u("POST /api/connect/enroll", s.apiEnrollToken)
	u("GET /api/qr", s.apiQR)
	m("GET /api/package", s.apiPackage)
	u("POST /api/package/link", s.apiPackageLink)
	u("GET /api/clients", s.apiClients)
	a("DELETE /api/clients/{id}", s.apiKick)
	u("GET /api/devices", s.apiDevices)
	a("DELETE /api/devices/{uid}", s.apiDeviceDelete)
	u("GET /api/cot/latest", s.apiLatest)
	u("GET /api/cot/history", s.apiHistory)
	u("POST /api/cot", s.apiPostCoT)
	u("DELETE /api/cot/{uid}", s.apiDeleteEvent)
	u("GET /api/cot/{uid}/image", s.apiEventImage)
	u("GET /api/tracks", s.apiTracks)
	u("GET /api/kml", s.apiKML)
	u("GET /api/stream", s.apiStream)
	u("GET /api/calls", s.apiCallsInfo)
	u("GET /api/calls/ws", s.apiCallsSocket)
	u("POST /api/chat", s.apiChat)
	u("POST /api/markers", s.apiMarker)
	u("GET /api/emergencies", s.apiEmergencies)
	a("GET /api/repeated", s.apiRepeatedList)
	a("GET /api/datafeeds", s.apiDataFeeds)
	u("GET /api/voice", s.apiVoice)
	a("DELETE /api/voice/users/{session}", s.apiVoiceKick)
	u("GET /api/video/streams", s.apiStreams)
	u("GET /api/video/recordings", s.apiRecordings)
	u("GET /api/video/recordings/{rest...}", s.apiRecordingFile)
	a("DELETE /api/video/recordings/{rest...}", s.apiRecordingFile)
	a("POST /api/video-record/{rest...}", s.apiRecordControl)
	a("DELETE /api/video-record/{rest...}", s.apiRecordControl)
	u("GET /api/video/live/{rest...}", s.apiLiveStream)
	a("DELETE /api/video/streams/{rest...}", s.apiStreamStop)
	a("POST /api/repeated/{uid}", s.apiRepeatedAdd)
	a("DELETE /api/repeated/{uid}", s.apiRepeatedDelete)
	a("GET /api/logs", s.apiLogs)
	a("GET /api/logs/stream", s.apiLogStream)
	a("GET /api/users", s.apiUsers)
	a("POST /api/users", s.apiUserCreate)
	a("GET /api/users/{name}", s.apiUserGet)
	a("PUT /api/users/{name}", s.apiUserUpdate)
	a("DELETE /api/users/{name}", s.apiUserDelete)
	a("POST /api/users/{name}/revoke", s.apiUserRevoke)
	a("POST /api/certs/{serial}/revoke", s.apiCertRevoke)
	a("POST /api/certs/server/renew", s.apiRenewServerCert)
	u("GET /api/groups", s.apiGroups)
	a("POST /api/groups", s.apiGroupCreate)
	a("DELETE /api/groups/{name}", s.apiGroupDelete)
	u("GET /api/tokens", s.apiTokens)
	u("POST /api/tokens", s.apiTokenCreate)
	u("DELETE /api/tokens/{id}", s.apiTokenDelete)
	u("GET /api/files", s.apiFiles)
	u("POST /api/files", s.apiFileUpload)
	u("PUT /api/files/{uid}", s.apiFileUpdate)
	u("DELETE /api/files/{uid}", s.martiFileDeleteByUID)
	u("POST /api/files/{uid}/share", s.apiFileShare)
	u("GET /api/files/{uid}/download", s.apiFileDownload)
	u("GET /api/missions", s.apiMissions)
	u("POST /api/missions", s.apiMissionCreate)
	u("GET /api/missions/{name}", s.apiMissionGet)
	u("DELETE /api/missions/{name}", s.apiMissionDelete)
	u("GET /api/video", s.apiVideos)
	u("POST /api/video", s.apiVideoCreate)
	u("DELETE /api/video/{uid}", s.apiVideoDelete)
	u("POST /api/video/{uid}/share", s.apiVideoShare)
	a("GET /api/profiles", s.apiProfiles)
	a("POST /api/profiles", s.apiProfileCreate)
	a("DELETE /api/profiles/{id}", s.apiProfileDelete)
	a("GET /api/plugins", s.apiPlugins)
	a("POST /api/plugins", s.apiPluginUpload)
	a("DELETE /api/plugins/{id}", s.apiPluginDelete)
	a("GET /api/settings", s.apiSettings)
	a("PUT /api/settings", s.apiSettingsUpdate)
	a("POST /api/restart", s.apiRestart)
	a("GET /api/cluster", s.apiClusterStatus)
	a("POST /api/cluster/invite", s.apiClusterInvite)
	a("POST /api/cluster/join", s.apiClusterJoin)
	a("POST /api/cluster/leave", s.apiClusterLeave)
	a("GET /api/update", s.apiUpdateStatus)
	a("POST /api/update/check", s.apiUpdateStatus)
	a("POST /api/update/install", s.apiUpdateInstall)
	a("GET /api/backup", s.apiBackup)
	a("GET /api/peers", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, http.StatusOK, s.peerStatus()) })
	a("GET /api/federation", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, http.StatusOK, s.federationStatus()) })
	a("GET /api/feeds", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, http.StatusOK, s.feedStatus()) })
	a("POST /api/ldap/test", s.apiLDAPTest)
	a("GET /api/performance", s.apiPerformance)
	a("GET /api/server-plugins", s.apiServerPluginsList)
	a("POST /api/links/invite", s.apiLinkInvite)
	a("POST /api/links/join", s.apiLinkJoin)
	a("GET /api/server-plugins/{name}/logs", s.apiServerPluginLogs)
	a("POST /api/server-plugins/{name}/{action}", s.apiServerPluginAction)
	a("PUT /api/server-plugins/{name}", s.apiServerPluginPut)
	a("PUT /api/server-plugins/{name}/settings", s.apiServerPluginSettings)
	u("GET /api/plugin-pages", s.apiPluginPages)
	pub("/plugins/{name}/{rest...}", s.pluginProxy)
	a("DELETE /api/server-plugins/{name}", s.apiServerPluginDelete)
	a("GET /api/meshtastic", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, http.StatusOK, s.meshStatus()) })

	mux.HandleFunc("/Marti/", s.martiUnknown)
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown API endpoint " + r.Method + " " + r.URL.Path})
	})
	assets := http.FileServerFS(web.Assets())
	mux.Handle("GET /assets/", http.StripPrefix("/assets/", noCache(assets)))
	mux.HandleFunc("GET /{$}", s.dashboardIndex)
	mux.HandleFunc("GET /favicon.ico", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	return mux
}

func noCache(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache")
		if strings.HasSuffix(r.URL.Path, ".woff2") {
			w.Header().Set("Content-Type", "font/woff2")
		}
		h.ServeHTTP(w, r)
	})
}

func (s *Server) dashboardIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data: blob: https: http:; media-src 'self' blob:; connect-src 'self' ws: wss:; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'")
	w.Write(web.Index())
}

func (s *Server) martiUnknown(w http.ResponseWriter, r *http.Request) {
	s.log.Debug("unhandled Marti request", "method", r.Method, "path", r.URL.Path, "query", r.URL.RawQuery, "agent", r.UserAgent())
	writeJSON(w, http.StatusNotFound, s.envelope("error", "not implemented: "+r.Method+" "+r.URL.Path))
}

func (s *Server) apiPortRoutes(mux *http.ServeMux) http.Handler {
	fts := s.ftsRoutes()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h, pattern := fts.Handler(r); pattern != "" {
			h.ServeHTTP(w, r)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func pathSegments(r *http.Request, prefix string) []string {
	p := strings.TrimPrefix(r.URL.EscapedPath(), prefix)
	p = strings.Trim(p, "/")
	if p == "" {
		return nil
	}
	parts := strings.Split(p, "/")
	for i, s := range parts {
		if v, err := url.PathUnescape(s); err == nil {
			parts[i] = v
		}
	}
	return parts
}

func (s *Server) missionRouter(w http.ResponseWriter, r *http.Request) {
	seg := pathSegments(r, "/Marti/api/missions")
	method := r.Method
	notFound := func() {
		s.martiUnknown(w, r)
	}
	if len(seg) == 0 {
		switch method {
		case http.MethodGet:
			s.missionList(w, r)
		case http.MethodDelete:
			s.missionDeleteByQuery(w, r)
		default:
			notFound()
		}
		return
	}
	switch {
	case len(seg) == 1 && seg[0] == "invitations" && method == http.MethodGet:
		s.missionInvitations(w, r)
		return
	case len(seg) == 3 && seg[0] == "all" && seg[1] == "subscriptions" && seg[2] == "guid":
		s.missionAllSubscriptionsGUID(w, r)
		return
	case len(seg) == 2 && seg[0] == "all":
		switch seg[1] {
		case "invitations":
			s.missionInvitations(w, r)
		case "subscriptions":
			s.missionAllSubscriptions(w, r)
		case "logs":
			s.missionAllLogs(w, r)
		default:
			notFound()
		}
		return
	case len(seg) >= 2 && seg[0] == "logs" && seg[1] == "entries":
		if len(seg) == 2 && (method == http.MethodPost || method == http.MethodPut) {
			s.missionLogCreate(w, r)
			return
		}
		if len(seg) == 3 {
			r.SetPathValue("id", seg[2])
			switch method {
			case http.MethodGet:
				s.missionLogGet(w, r)
				return
			case http.MethodDelete:
				s.missionLogDelete(w, r)
				return
			}
		}
		notFound()
		return
	case len(seg) == 1 && seg[0] == "exchecktemplates", len(seg) == 1 && seg[0] == "ExCheckTemplates":
		s.excheckTemplateMission(w, r)
		return
	}
	if seg[0] == "guid" {
		if len(seg) < 2 {
			notFound()
			return
		}
		r.SetPathValue("guid", seg[1])
		if mm, ok := s.missions.ByGUID(seg[1]); ok {
			r.SetPathValue("name", mm.Name)
		}
		seg = seg[2:]
	} else {
		r.SetPathValue("name", seg[0])
		seg = seg[1:]
	}
	action := ""
	if len(seg) > 0 {
		action = seg[0]
	}
	switch action {
	case "":
		switch method {
		case http.MethodGet:
			s.missionGet(w, r)
		case http.MethodPut, http.MethodPost:
			if r.PathValue("guid") != "" {
				notFound()
				return
			}
			s.missionCreate(w, r)
		case http.MethodDelete:
			s.missionDelete(w, r)
		default:
			notFound()
		}
	case "subscription":
		switch method {
		case http.MethodPut, http.MethodPost:
			s.missionSubscribe(w, r)
		case http.MethodGet:
			s.missionSubscription(w, r)
		case http.MethodDelete:
			s.missionUnsubscribe(w, r)
		default:
			notFound()
		}
	case "subscriptions":
		if len(seg) == 2 && seg[1] == "roles" {
			s.missionRoles(w, r)
			return
		}
		s.missionSubscriptions(w, r)
	case "role":
		if method == http.MethodPut {
			s.missionSetRole(w, r)
		} else {
			s.missionMyRole(w, r)
		}
	case "contents":
		switch {
		case len(seg) == 2 && seg[1] == "missionpackage" && (method == http.MethodPut || method == http.MethodPost):
			s.missionContentsPackage(w, r)
		case method == http.MethodPut || method == http.MethodPost:
			s.missionContentsAdd(w, r)
		case method == http.MethodDelete:
			s.missionContentsRemove(w, r)
		case method == http.MethodGet:
			s.missionContentsList(w, r)
		default:
			notFound()
		}
	case "changes":
		s.missionChanges(w, r)
	case "cot":
		s.missionCoT(w, r)
	case "log":
		s.missionLogs(w, r)
	case "kml":
		s.missionKML(w, r)
	case "archive":
		s.missionArchive(w, r)
	case "keywords":
		if len(seg) == 2 {
			r.SetPathValue("keyword", seg[1])
		}
		s.missionKeywords(w, r)
	case "password":
		s.missionPassword(w, r)
	case "expiration":
		s.missionExpiration(w, r)
	case "invite":
		if len(seg) == 3 {
			r.SetPathValue("type", seg[1])
			r.SetPathValue("invitee", seg[2])
			if method == http.MethodDelete {
				s.missionUninvite(w, r)
			} else {
				s.missionInvite(w, r)
			}
			return
		}
		if method == http.MethodPost {
			s.missionInvite(w, r)
			return
		}
		notFound()
	case "invitations":
		s.missionInvitations(w, r)
	case "contacts":
		s.missionContacts(w, r)
	case "parent":
		if len(seg) == 2 {
			r.SetPathValue("parent", seg[1])
			s.missionSetParent(w, r)
			return
		}
		if method == http.MethodDelete {
			s.missionSetParent(w, r)
			return
		}
		s.missionParent(w, r)
	case "children":
		s.missionChildren(w, r)
	case "externaldata":
		if len(seg) == 2 {
			r.SetPathValue("id", seg[1])
		}
		s.missionExternalData(w, r)
	case "feed", "feeds":
		switch {
		case len(seg) == 1 && (method == http.MethodPost || method == http.MethodPut):
			s.missionFeedAdd(w, r)
		case len(seg) == 2 && method == http.MethodDelete:
			r.SetPathValue("uid", seg[1])
			s.missionFeedDelete(w, r)
		case len(seg) == 1 && method == http.MethodGet:
			if mm, ok := s.loadMissionAny(w, r); ok {
				out := []map[string]any{}
				for _, f := range mm.Feeds {
					out = append(out, s.missionFeedJSON(f))
				}
				writeJSON(w, http.StatusOK, s.envelope("MissionFeed", out))
			}
		default:
			notFound()
		}
	case "maplayers":
		switch {
		case len(seg) == 1 && (method == http.MethodPost || method == http.MethodPut):
			s.missionMapLayerSave(w, r)
		case len(seg) == 2 && method == http.MethodDelete:
			r.SetPathValue("uid", seg[1])
			s.missionMapLayerDelete(w, r)
		case len(seg) == 1 && method == http.MethodGet:
			if mm, ok := s.loadMissionAny(w, r); ok {
				layers := mm.MapLayers
				if layers == nil {
					layers = []MapLayer{}
				}
				writeJSON(w, http.StatusOK, s.envelope("MapLayer", layers))
			}
		default:
			notFound()
		}
	case "properties":
		key := ""
		if len(seg) == 2 {
			key = seg[1]
		}
		s.missionProperties(w, r, key)
	case "layers":
		s.missionLayers(w, r, seg[1:])
	case "copy":
		if method == http.MethodPut || method == http.MethodPost {
			s.missionCopy(w, r)
		} else {
			notFound()
		}
	case "send":
		if method == http.MethodPost || method == http.MethodPut {
			s.missionSend(w, r)
		} else {
			notFound()
		}
	case "token":
		s.missionAccessToken(w, r)
	case "content", "uid":
		if len(seg) == 3 && seg[2] == "keywords" && (method == http.MethodPut || method == http.MethodDelete) {
			s.missionItemKeywords(w, r, action, seg[1])
			return
		}
		notFound()
	default:
		notFound()
	}
}
