package server

import (
	"archive/zip"
	"bytes"
	"encoding/csv"
	"errors"
	"html"
	"io"
	"mime"
	"net/http"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/cot"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/store"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/xmltree"
)

const (
	exTemplates = "exchecktemplates"
	exTool      = "ExCheck"
)

func childText(n *xmltree.Node, name string) string {
	if c := n.Child(name); c != nil {
		return strings.TrimSpace(c.Text)
	}
	return ""
}

func setChildText(n *xmltree.Node, name, v string) {
	c := n.Child(name)
	if c == nil {
		c = n.AddNew(name)
	}
	c.Children = nil
	c.Text = v
}

func xmlDoc(n *xmltree.Node) []byte {
	return append([]byte(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>`), n.AppendXML(nil)...)
}

func (s *Server) ensureExCheckTemplates() {
	s.missions.db.Update(exTemplates, func(m Mission, exists bool) (Mission, bool, error) {
		if exists {
			return m, true, nil
		}
		return Mission{Name: exTemplates, GUID: cot.NewUID(), Description: "ExCheck templates", Tool: exTool, Created: time.Now().UTC(), DefaultRole: RoleSubscriber, Expiration: -1, Keywords: []string{}}, true, nil
	})
}

func (s *Server) storeXMLResource(uid string, data []byte, keywords []string, submitter, tool string, groups []string) (Resource, error) {
	hash, err := s.res.blobs.PutBytes(data)
	if err != nil {
		return Resource{}, err
	}
	old, hadOld := s.res.db.Get(uid)
	res := Resource{UID: uid, Hash: hash, Name: uid, MIMEType: "application/xml", Size: int64(len(data)), Keywords: keywords, Tool: tool,
		Submitter: submitter, Submitted: time.Now().UTC(), Groups: groups, Expiration: -1}
	if hadOld {
		res.Key = old.Key
	}
	if err := s.res.Put(res); err != nil {
		return Resource{}, err
	}
	if hadOld && old.Hash != hash && !s.missionUsesHash(old.Hash) {
		inUse := false
		for _, r := range s.res.All() {
			if r.Hash == old.Hash {
				inUse = true
				break
			}
		}
		if !inUse {
			s.res.blobs.Delete(old.Hash)
		}
	}
	return res, nil
}

func (s *Server) missionPutContent(name string, res Resource, creator string) (Mission, error) {
	m, err := s.missions.Update(name, func(x *Mission) error {
		x.Contents = slices.DeleteFunc(x.Contents, func(c MissionContent) bool { return c.UID == res.UID })
		x.Contents = append(x.Contents, MissionContent{UID: res.UID, Hash: res.Hash, CreatorUID: creator, Added: time.Now().UTC()})
		rc := res
		x.addChange(MissionChange{Type: "ADD_CONTENT", CreatorUID: creator, ContentUID: res.UID, Resource: &rc})
		return nil
	})
	if err == nil {
		s.notifyMissionChange(m, "ADD_CONTENT", creator, &res, nil)
	}
	return m, err
}

func (s *Server) missionDropContent(name, uid, creator string) (Mission, error) {
	var removed *Resource
	m, err := s.missions.Update(name, func(x *Mission) error {
		idx := slices.IndexFunc(x.Contents, func(c MissionContent) bool { return c.UID == uid })
		if idx < 0 {
			return errMissionNotFound
		}
		res, _ := s.res.Get(uid)
		if res.UID == "" {
			res = Resource{UID: uid, Hash: x.Contents[idx].Hash}
		}
		x.Contents = slices.Delete(x.Contents, idx, idx+1)
		removed = &res
		x.addChange(MissionChange{Type: "REMOVE_CONTENT", CreatorUID: creator, ContentUID: uid, Resource: &res})
		return nil
	})
	if err == nil && removed != nil {
		s.notifyMissionChange(m, "REMOVE_CONTENT", creator, removed, nil)
	}
	return m, err
}

func parseCSVTemplate(data []byte) (*xmltree.Node, error) {
	r := csv.NewReader(bytes.NewReader(bytes.ReplaceAll(data, []byte("\r"), nil)))
	r.FieldsPerRecord = -1
	r.LazyQuotes = true
	rows, err := r.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(rows) < 3 {
		return nil, errors.New("a checklist template needs a header row, a format row and at least one task")
	}
	cl := xmltree.New("checklist")
	details := cl.AddNew("checklistDetails")
	setChildText(details, "uid", cot.NewUID())
	cols := cl.AddNew("checklistColumns")
	header := rows[0][1:]
	format := rows[1][1:]
	notesIdx := -1
	for i, name := range header {
		name = strings.TrimSpace(name)
		if strings.EqualFold(name, "notes") {
			notesIdx = i
			continue
		}
		col := cols.AddNew("checklistColumn")
		setChildText(col, "columnName", name)
		if i < len(format) {
			for _, kv := range strings.Split(format[i], "|") {
				k, v, ok := strings.Cut(kv, "=")
				if !ok {
					continue
				}
				switch strings.ToLower(strings.TrimSpace(k)) {
				case "type":
					setChildText(col, "columnType", v)
				case "width":
					setChildText(col, "columnWidth", v)
				case "bgcolor":
					setChildText(col, "columnBgColor", v)
				case "textcolor":
					setChildText(col, "columnTextColor", v)
				case "editable":
					setChildText(col, "columnEditable", v)
				}
			}
		}
		if childText(col, "columnType") == "" {
			setChildText(col, "columnType", "ShortString")
		}
	}
	tasks := cl.AddNew("checklistTasks")
	for _, row := range rows[2:] {
		if len(row) == 0 || (len(row) == 1 && strings.TrimSpace(row[0]) == "") {
			continue
		}
		task := xmltree.New("checklistTask")
		setChildText(task, "uid", cot.NewUID())
		for _, kv := range strings.Split(row[0], "|") {
			k, v, ok := strings.Cut(kv, "=")
			if !ok {
				continue
			}
			switch strings.ToLower(strings.TrimSpace(k)) {
			case "break":
				setChildText(task, "lineBreak", strings.ToLower(strings.TrimSpace(v)))
			case "bgcolor":
				setChildText(task, "bgColor", v)
			}
		}
		for i := 0; i < len(header); i++ {
			v := ""
			if i+1 < len(row) {
				v = strings.TrimSpace(row[i+1])
			}
			if i == notesIdx {
				if v != "" {
					setChildText(task, "notes", v)
				}
				continue
			}
			if v == "" {
				v = " "
			}
			task.AddNew("value").Text = v
		}
		setChildText(task, "status", "Pending")
		tasks.Add(task)
	}
	return cl, nil
}

func (s *Server) readExCheckBody(w http.ResponseWriter, r *http.Request) ([]byte, string, error) {
	mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if strings.HasPrefix(mt, "multipart/") {
		src, _, _, done, err := s.readUpload(w, r)
		if err != nil {
			return nil, "", err
		}
		defer done()
		b, err := io.ReadAll(io.LimitReader(src, 16<<20))
		return b, "csv", err
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, 16<<20))
	if err != nil {
		return nil, "", err
	}
	if strings.Contains(mt, "xml") || bytes.HasPrefix(bytes.TrimSpace(b), []byte("<")) {
		return b, "xml", nil
	}
	return b, "csv", nil
}

func (s *Server) excheckTemplatePost(w http.ResponseWriter, r *http.Request) {
	id := identityOf(r)
	q := r.URL.Query()
	clientUID := q.Get("clientUid")
	body, kind, err := s.readExCheckBody(w, r)
	if err != nil {
		writeText(w, http.StatusBadRequest, err.Error())
		return
	}
	var cl *xmltree.Node
	if kind == "xml" {
		cl, err = xmltree.Parse(body)
		if err == nil && cl.Name != "checklist" {
			err = errors.New("root element must be <checklist>")
		}
	} else {
		cl, err = parseCSVTemplate(body)
	}
	if err != nil {
		writeText(w, http.StatusBadRequest, "invalid checklist template: "+err.Error())
		return
	}
	details := cl.Child("checklistDetails")
	if details == nil {
		details = cl.AddNew("checklistDetails")
	}
	uid := childText(details, "uid")
	if uid == "" {
		uid = cot.NewUID()
		setChildText(details, "uid", uid)
	}
	name := firstNonEmpty(q.Get("name"), childText(details, "name"), childText(details, "templateName"), "Checklist")
	desc := firstNonEmpty(q.Get("description"), childText(details, "description"))
	callsign := firstNonEmpty(q.Get("callsign"), childText(details, "creatorCallsign"))
	setChildText(details, "name", name)
	setChildText(details, "templateName", name)
	setChildText(details, "description", desc)
	setChildText(details, "creatorUid", clientUID)
	setChildText(details, "creatorCallsign", callsign)
	if ts := cl.Child("checklistTasks"); ts != nil {
		for _, t := range ts.All("checklistTask") {
			if childText(t, "uid") == "" {
				setChildText(t, "uid", cot.NewUID())
			}
		}
	}
	s.ensureExCheckTemplates()
	res, err := s.storeXMLResource(uid, xmlDoc(cl), []string{name, desc, callsign}, id.Name, exTool, nil)
	if err != nil {
		writeText(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.missionPutContent(exTemplates, res, clientUID)
	s.log.Info("checklist template saved", "name", name, "uid", uid, "by", id.Name)
	writeText(w, http.StatusOK, uid)
}

func (s *Server) loadXMLResource(uid string) (*xmltree.Node, Resource, bool) {
	res, ok := s.res.Get(uid)
	if !ok {
		return nil, res, false
	}
	data, err := s.res.blobs.Read(res.Hash)
	if err != nil {
		return nil, res, false
	}
	n, err := xmltree.Parse(data)
	if err != nil {
		return nil, res, false
	}
	return n, res, true
}

func (s *Server) excheckTemplateGet(w http.ResponseWriter, r *http.Request) {
	n, _, ok := s.loadXMLResource(r.PathValue("uid"))
	if !ok {
		writeText(w, http.StatusNotFound, "template not found")
		return
	}
	writeXML(w, http.StatusOK, string(xmlDoc(n)))
}

func (s *Server) excheckTemplateDelete(w http.ResponseWriter, r *http.Request) {
	uid := r.PathValue("uid")
	res, ok := s.res.Get(uid)
	if !ok || !s.resourceVisible(identityOf(r), res) {
		writeText(w, http.StatusNotFound, "template not found")
		return
	}
	if !s.canEdit(identityOf(r), res) {
		writeText(w, http.StatusForbidden, "only the author or an administrator can delete this template")
		return
	}
	if _, err := s.missionDropContent(exTemplates, uid, r.URL.Query().Get("clientUid")); err != nil {
		writeText(w, http.StatusNotFound, "template not found")
		return
	}
	s.res.Delete(uid)
	w.WriteHeader(http.StatusOK)
}

func (s *Server) excheckTemplateTask(w http.ResponseWriter, r *http.Request) {
	uid, taskUID := r.PathValue("uid"), r.PathValue("task")
	cl, res, ok := s.loadXMLResource(uid)
	if !ok || !s.resourceVisible(identityOf(r), res) {
		writeText(w, http.StatusNotFound, "template not found")
		return
	}
	if r.Method != http.MethodGet && !s.canEdit(identityOf(r), res) {
		writeText(w, http.StatusForbidden, "only the author or an administrator can change this template")
		return
	}
	tasks := cl.Child("checklistTasks")
	if tasks == nil {
		tasks = cl.AddNew("checklistTasks")
	}
	var found *xmltree.Node
	for _, t := range tasks.All("checklistTask") {
		if childText(t, "uid") == taskUID {
			found = t
		}
	}
	switch r.Method {
	case http.MethodGet:
		if found == nil {
			writeText(w, http.StatusNotFound, "task not found")
			return
		}
		writeXML(w, http.StatusOK, string(xmlDoc(found)))
		return
	case http.MethodDelete:
		if found == nil {
			writeText(w, http.StatusNotFound, "task not found")
			return
		}
		tasks.Remove(found)
	default:
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			writeText(w, http.StatusBadRequest, err.Error())
			return
		}
		task, err := xmltree.Parse(body)
		if err != nil || task.Name != "checklistTask" || childText(task, "uid") != taskUID {
			writeText(w, http.StatusBadRequest, "body must be a <checklistTask> with a matching uid")
			return
		}
		if found != nil {
			*found = *task
		} else {
			tasks.Add(task)
		}
	}
	d := cl.Child("checklistDetails")
	kw := []string{childText(d, "name"), childText(d, "description")}
	nres, err := s.storeXMLResource(uid, xmlDoc(cl), kw, res.Submitter, exTool, res.Groups)
	if err != nil {
		writeText(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.missionPutContent(exTemplates, nres, r.URL.Query().Get("clientUid"))
	if r.Method == http.MethodPut && found == nil {
		w.WriteHeader(http.StatusCreated)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) createChecklistMission(r *http.Request, cl *xmltree.Node, clientUID, defaultRole string) (Mission, error) {
	id := identityOf(r)
	details := cl.Child("checklistDetails")
	uid := childText(details, "uid")
	tasks := cl.Child("checklistTasks")
	var taskNodes []*xmltree.Node
	if tasks != nil {
		taskNodes = tasks.All("checklistTask")
	}
	skeleton := cl.Clone()
	if st := skeleton.Child("checklistTasks"); st != nil {
		st.Children = nil
	}
	groups := s.identityGroups(id)
	role := normalizeRole(defaultRole)
	if role == "" {
		role = RoleSubscriber
	}
	s.ensureExCheckTemplates()
	_, err := s.missions.db.Update(uid, func(m Mission, exists bool) (Mission, bool, error) {
		if exists {
			return m, true, nil
		}
		m = Mission{Name: uid, GUID: cot.NewUID(), Description: childText(details, "description"), Tool: exTool, Created: time.Now().UTC(),
			CreatorUID: clientUID, CreatorUser: id.Name, Groups: groups, DefaultRole: role, Expiration: -1, Keywords: []string{}, Parent: exTemplates}
		if clientUID != "" {
			m.Subs = append(m.Subs, MissionSub{ClientUID: clientUID, Username: id.Name, Role: RoleOwner, Created: time.Now().UTC()})
		}
		m.addChange(MissionChange{Type: "CREATE_MISSION", CreatorUID: clientUID})
		return m, true, nil
	})
	if err != nil {
		return Mission{}, err
	}
	res, err := s.storeXMLResource(uid, xmlDoc(skeleton), []string{"Template"}, id.Name, exTool, groups)
	if err != nil {
		return Mission{}, err
	}
	s.missionPutContent(uid, res, clientUID)
	for i, t := range taskNodes {
		if childText(t, "uid") == "" {
			setChildText(t, "uid", cot.NewUID())
		}
		if childText(t, "number") == "" {
			setChildText(t, "number", strconv.Itoa(i))
		}
		tr, err := s.storeXMLResource(childText(t, "uid"), xmlDoc(t), []string{"Task"}, id.Name, exTool, groups)
		if err != nil {
			return Mission{}, err
		}
		s.missionPutContent(uid, tr, clientUID)
	}
	m, _ := s.missions.Get(uid)
	return m, nil
}

func (s *Server) assembleChecklist(m Mission, detailsOnly bool) (*xmltree.Node, error) {
	var cl *xmltree.Node
	var tasks []*xmltree.Node
	for _, c := range m.Contents {
		res, ok := s.res.Get(c.UID)
		if !ok {
			continue
		}
		data, err := s.res.blobs.Read(res.Hash)
		if err != nil {
			continue
		}
		n, err := xmltree.Parse(data)
		if err != nil {
			continue
		}
		switch {
		case n.Name == "checklist" && cl == nil:
			cl = n
		case n.Name == "checklistTask" && !detailsOnly:
			tasks = append(tasks, n)
		}
	}
	if cl == nil {
		return nil, errors.New("checklist content missing")
	}
	sort.SliceStable(tasks, func(i, j int) bool {
		a, _ := strconv.Atoi(childText(tasks[i], "number"))
		b, _ := strconv.Atoi(childText(tasks[j], "number"))
		return a < b
	})
	ct := cl.Child("checklistTasks")
	if ct == nil {
		ct = cl.AddNew("checklistTasks")
	}
	ct.Children = tasks
	if detailsOnly {
		if cc := cl.Child("checklistColumns"); cc != nil {
			cc.Children = nil
		}
	}
	return cl, nil
}

func (s *Server) excheckStart(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	tpl, _, ok := s.loadXMLResource(r.PathValue("uid"))
	if !ok {
		writeText(w, http.StatusNotFound, "template not found")
		return
	}
	details := tpl.Child("checklistDetails")
	if details == nil {
		details = tpl.AddNew("checklistDetails")
	}
	uid := cot.NewUID()
	setChildText(details, "uid", uid)
	setChildText(details, "name", firstNonEmpty(q.Get("name"), childText(details, "name")))
	setChildText(details, "description", firstNonEmpty(q.Get("description"), childText(details, "description")))
	setChildText(details, "startTime", firstNonEmpty(q.Get("startTime"), cot.FormatTime(time.Now())))
	setChildText(details, "creatorUid", q.Get("clientUid"))
	setChildText(details, "creatorCallsign", q.Get("callsign"))
	if ts := tpl.Child("checklistTasks"); ts != nil {
		for i, t := range ts.All("checklistTask") {
			setChildText(t, "uid", cot.NewUID())
			setChildText(t, "number", strconv.Itoa(i))
		}
	}
	m, err := s.createChecklistMission(r, tpl.Clone(), q.Get("clientUid"), q.Get("defaultRole"))
	if err != nil {
		writeText(w, http.StatusInternalServerError, err.Error())
		return
	}
	cl, err := s.assembleChecklist(m, false)
	if err != nil {
		writeText(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.log.Info("checklist started", "name", childText(details, "name"), "uid", uid)
	writeXML(w, http.StatusOK, string(xmlDoc(cl)))
}

func (s *Server) excheckChecklistPost(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 16<<20))
	if err != nil {
		writeText(w, http.StatusBadRequest, err.Error())
		return
	}
	cl, err := xmltree.Parse(body)
	if err != nil || cl.Name != "checklist" {
		writeText(w, http.StatusBadRequest, "body must be a <checklist>")
		return
	}
	details := cl.Child("checklistDetails")
	if details == nil {
		details = cl.AddNew("checklistDetails")
	}
	uid := childText(details, "uid")
	if uid == "" {
		uid = cot.NewUID()
		setChildText(details, "uid", uid)
	}
	q := r.URL.Query()
	if existing, ok := s.missions.Get(uid); ok {
		if !s.missionVisible(identityOf(r), existing) {
			writeText(w, http.StatusForbidden, "forbidden")
			return
		}
		if ts := cl.Child("checklistTasks"); ts != nil {
			for _, t := range ts.All("checklistTask") {
				if childText(t, "uid") == "" {
					setChildText(t, "uid", cot.NewUID())
				}
				tr, err := s.storeXMLResource(childText(t, "uid"), xmlDoc(t), []string{"Task"}, identityOf(r).Name, exTool, existing.Groups)
				if err == nil {
					s.missionPutContent(uid, tr, q.Get("clientUid"))
				}
			}
		}
		skeleton := cl.Clone()
		if st := skeleton.Child("checklistTasks"); st != nil {
			st.Children = nil
		}
		if res, err := s.storeXMLResource(uid, xmlDoc(skeleton), []string{"Template"}, identityOf(r).Name, exTool, existing.Groups); err == nil {
			s.missionPutContent(uid, res, q.Get("clientUid"))
		}
	} else if _, err := s.createChecklistMission(r, cl, q.Get("clientUid"), q.Get("defaultRole")); err != nil {
		writeText(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeText(w, http.StatusOK, uid)
}

func (s *Server) excheckActive(w http.ResponseWriter, r *http.Request) {
	id := identityOf(r)
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?><checklists>`)
	for _, m := range s.missions.All() {
		if m.Parent != exTemplates || !s.missionVisible(id, m) {
			continue
		}
		cl, err := s.assembleChecklist(m, true)
		if err != nil {
			continue
		}
		d := cl.Child("checklistDetails")
		if d == nil {
			continue
		}
		b.WriteString("<checklist>")
		b.WriteString(d.String())
		b.WriteString("<checklistColumns/><checklistTasks/></checklist>")
	}
	b.WriteString("</checklists>")
	writeXML(w, http.StatusOK, b.String())
}

func (s *Server) checklistMission(w http.ResponseWriter, r *http.Request) (Mission, bool) {
	m, ok := s.missions.Get(r.PathValue("uid"))
	if !ok || m.Tool != exTool {
		writeText(w, http.StatusNotFound, "checklist not found")
		return m, false
	}
	if !s.missionVisible(identityOf(r), m) {
		writeText(w, http.StatusForbidden, "forbidden")
		return m, false
	}
	return m, true
}

func (s *Server) excheckChecklistGet(w http.ResponseWriter, r *http.Request) {
	m, ok := s.checklistMission(w, r)
	if !ok {
		return
	}
	cl, err := s.assembleChecklist(m, false)
	if err != nil {
		writeText(w, http.StatusNotFound, err.Error())
		return
	}
	writeXML(w, http.StatusOK, string(xmlDoc(cl)))
}

func (s *Server) excheckStop(w http.ResponseWriter, r *http.Request) {
	m, ok := s.checklistMission(w, r)
	if !ok {
		return
	}
	if !s.requirePermission(w, r, m, "MISSION_DELETE") {
		return
	}
	s.missions.db.Delete(m.Name)
	for _, c := range m.Contents {
		if !s.missionUsesHash(c.Hash) {
			s.res.Delete(c.UID)
		}
	}
	s.notifyMissionAll(m, "t-x-m-d", "DELETE", r.URL.Query().Get("clientUid"))
	w.WriteHeader(http.StatusOK)
}

func (s *Server) excheckTask(w http.ResponseWriter, r *http.Request) {
	m, ok := s.checklistMission(w, r)
	if !ok {
		return
	}
	taskUID := r.PathValue("task")
	clientUID := r.URL.Query().Get("clientUid")
	if r.Method != http.MethodGet && !s.requirePermission(w, r, m, "MISSION_WRITE") {
		return
	}
	switch r.Method {
	case http.MethodGet:
		n, _, ok := s.loadXMLResource(taskUID)
		if !ok {
			writeText(w, http.StatusNotFound, "task not found")
			return
		}
		writeXML(w, http.StatusOK, string(xmlDoc(n)))
		return
	case http.MethodDelete:
		if _, err := s.missionDropContent(m.Name, taskUID, clientUID); err != nil {
			writeText(w, http.StatusNotFound, "task not found")
			return
		}
		s.res.Delete(taskUID)
		w.WriteHeader(http.StatusOK)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeText(w, http.StatusBadRequest, err.Error())
		return
	}
	task, err := xmltree.Parse(body)
	if err != nil || task.Name != "checklistTask" || childText(task, "uid") != taskUID {
		writeText(w, http.StatusBadRequest, "body must be a <checklistTask> with a matching uid")
		return
	}
	existed := slices.ContainsFunc(m.Contents, func(c MissionContent) bool { return c.UID == taskUID })
	var previous *xmltree.Node
	if existed {
		previous, _, _ = s.loadXMLResource(taskUID)
	}
	res, err := s.storeXMLResource(taskUID, xmlDoc(task), []string{"Task"}, identityOf(r).Name, exTool, m.Groups)
	if err != nil {
		writeText(w, http.StatusInternalServerError, err.Error())
		return
	}
	m, _ = s.missionPutContent(m.Name, res, clientUID)
	op := "added"
	if previous != nil {
		op = "updated"
		prevStatus := childText(previous, "status")
		newStatus := childText(task, "status")
		if strings.EqualFold(prevStatus, "Pending") && (strings.EqualFold(newStatus, "Complete") || strings.EqualFold(newStatus, "Late")) {
			op = "completed"
		}
	}
	s.notifyChecklistReferences(m, task, op, clientUID, res.Hash)
	if existed {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusCreated)
	}
}

func (s *Server) notifyChecklistReferences(m Mission, task *xmltree.Node, op, clientUID, hash string) {
	cl, err := s.assembleChecklist(m, true)
	if err != nil {
		return
	}
	d := cl.Child("checklistDetails")
	ms := d.Child("missions")
	if ms == nil {
		return
	}
	who := clientUID
	if dev, ok := s.devices.Get(clientUID); ok && dev.Callsign != "" {
		who = dev.Callsign
	}
	notes := who + " " + op + " " + childText(d, "name")
	if vals := task.All("value"); len(vals) > 0 {
		notes += "; " + strings.TrimSpace(vals[0].Text)
	}
	for _, mn := range ms.All("mission") {
		ref, ok := s.missions.Get(strings.TrimSpace(mn.Text))
		if !ok {
			continue
		}
		ref, _ = s.missions.Update(ref.Name, func(x *Mission) error {
			for _, ed := range x.ExternalData {
				if id, _ := ed["id"].(string); id == m.Name {
					ed["notes"] = notes
				}
			}
			x.addChange(MissionChange{Type: "CHANGE", CreatorUID: clientUID})
			return nil
		})
		e := s.missionEvent(ref, "t-x-m-c-e", "CHANGE", clientUID)
		s.sendToSubscribers(ref, e, "")
	}
}

func (s *Server) excheckStatus(w http.ResponseWriter, r *http.Request) {
	m, ok := s.checklistMission(w, r)
	if !ok {
		return
	}
	cl, err := s.assembleChecklist(m, false)
	if err != nil {
		writeText(w, http.StatusNotFound, err.Error())
		return
	}
	total, done := 0, 0
	for _, t := range cl.Child("checklistTasks").All("checklistTask") {
		if strings.EqualFold(childText(t, "lineBreak"), "true") {
			continue
		}
		total++
		if st := childText(t, "status"); strings.EqualFold(st, "Complete") || strings.EqualFold(st, "Late") {
			done++
		}
	}
	name := childText(cl.Child("checklistDetails"), "name")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte("<html><body><h2>Checklist : " + html.EscapeString(name) + "</h2><h3>Progress : " + strconv.Itoa(done) + "/" + strconv.Itoa(total) +
		"</h3><progress value=\"" + strconv.Itoa(done) + "\" max=\"" + strconv.Itoa(total) + "\"></progress></body></html>"))
}

func (s *Server) excheckMissionRef(w http.ResponseWriter, r *http.Request) {
	m, ok := s.checklistMission(w, r)
	if !ok {
		return
	}
	target, ok := s.missions.Get(r.PathValue("mission"))
	if !ok || !s.missionVisible(identityOf(r), target) {
		writeText(w, http.StatusNotFound, "mission not found")
		return
	}
	if !s.canWriteMission(r, m) || !s.canWriteMission(r, target) {
		writeText(w, http.StatusForbidden, "your mission role does not allow MISSION_WRITE")
		return
	}
	clientUID := r.URL.Query().Get("clientUid")
	cl, err := s.assembleChecklist(m, true)
	if err != nil {
		writeText(w, http.StatusNotFound, err.Error())
		return
	}
	d := cl.Child("checklistDetails")
	ms := d.Child("missions")
	if ms == nil {
		ms = d.AddNew("missions")
	}
	has := false
	for _, x := range ms.All("mission") {
		if strings.EqualFold(strings.TrimSpace(x.Text), target.Name) {
			has = true
			if r.Method == http.MethodDelete {
				ms.Remove(x)
			}
		}
	}
	if r.Method != http.MethodDelete && !has {
		ms.AddNew("mission").Text = target.Name
	}
	cl.Child("checklistTasks").Children = nil
	if res, err := s.storeXMLResource(m.Name, xmlDoc(cl), []string{"Template"}, identityOf(r).Name, exTool, m.Groups); err == nil {
		s.missionPutContent(m.Name, res, clientUID)
	}
	base := s.baseURL(r)
	target, _ = s.missions.Update(target.Name, func(x *Mission) error {
		x.ExternalData = slices.DeleteFunc(x.ExternalData, func(ed map[string]any) bool { id, _ := ed["id"].(string); return id == m.Name })
		if r.Method != http.MethodDelete {
			x.ExternalData = append(x.ExternalData, map[string]any{
				"id": m.Name, "name": childText(d, "name"), "tool": exTool,
				"urlData": base + "/Marti/api/excheck/checklist/" + m.Name, "urlView": base + "/Marti/api/excheck/checklist/" + m.Name + "/status",
				"notes": "checklist " + childText(d, "name"),
			})
		}
		x.addChange(MissionChange{Type: "CHANGE", CreatorUID: clientUID})
		return nil
	})
	s.sendToSubscribers(target, s.missionEvent(target, "t-x-m-c-e", "CHANGE", clientUID), "")
	w.WriteHeader(http.StatusOK)
}

func (s *Server) excheckTemplateMission(w http.ResponseWriter, r *http.Request) {
	s.ensureExCheckTemplates()
	r.SetPathValue("name", exTemplates)
	s.missionGet(w, r)
}

func (s *Server) excheckRoutes(m func(string, http.HandlerFunc)) {
	m("POST /Marti/api/excheck/template", s.excheckTemplatePost)
	m("GET /Marti/api/excheck/template/{uid}", s.excheckTemplateGet)
	m("DELETE /Marti/api/excheck/template/{uid}", s.excheckTemplateDelete)
	m("GET /Marti/api/excheck/template/{uid}/task/{task}", s.excheckTemplateTask)
	m("PUT /Marti/api/excheck/template/{uid}/task/{task}", s.excheckTemplateTask)
	m("POST /Marti/api/excheck/template/{uid}/task/{task}", s.excheckTemplateTask)
	m("DELETE /Marti/api/excheck/template/{uid}/task/{task}", s.excheckTemplateTask)
	m("POST /Marti/api/excheck/{uid}/start", s.excheckStart)
	m("POST /Marti/api/excheck/{uid}/stop", s.excheckStop)
	m("POST /Marti/api/excheck/checklist", s.excheckChecklistPost)
	m("POST /Marti/api/excheck/checklist/{$}", s.excheckChecklistPost)
	m("GET /Marti/api/excheck/checklist/active", s.excheckActive)
	m("GET /Marti/api/excheck/checklist/{uid}", s.excheckChecklistGet)
	m("DELETE /Marti/api/excheck/checklist/{uid}", s.excheckStop)
	m("GET /Marti/api/excheck/checklist/{uid}/status", s.excheckStatus)
	m("GET /Marti/api/excheck/checklist/{uid}/task/{task}", s.excheckTask)
	m("PUT /Marti/api/excheck/checklist/{uid}/task/{task}", s.excheckTask)
	m("DELETE /Marti/api/excheck/checklist/{uid}/task/{task}", s.excheckTask)
	m("PUT /Marti/api/excheck/checklist/{uid}/mission/{mission}", s.excheckMissionRef)
	m("DELETE /Marti/api/excheck/checklist/{uid}/mission/{mission}", s.excheckMissionRef)
}

type CITrapReport struct {
	ID                  string    `json:"id"`
	Type                string    `json:"type"`
	Title               string    `json:"title"`
	UserCallsign        string    `json:"userCallsign"`
	UserDescription     string    `json:"userDescription"`
	DateTime            time.Time `json:"dateTime"`
	DateTimeDescription string    `json:"dateTimeDescription"`
	Location            string    `json:"location"`
	LocationDescription string    `json:"locationDescription"`
	EventScale          string    `json:"eventScale"`
	Importance          string    `json:"importance"`
	Status              string    `json:"status"`
	Tags                string    `json:"tags"`
	ClientUID           string    `json:"clientUid"`
	Hash                string    `json:"hash"`
	Groups              []string  `json:"groups"`
	Lat                 float64   `json:"lat"`
	Lon                 float64   `json:"lon"`
}

func (r CITrapReport) martiJSON() map[string]any {
	return map[string]any{
		"dateTime": isoTime(r.DateTime), "userDescription": r.UserDescription, "importance": r.Importance,
		"locationDescription": r.LocationDescription, "userCallsign": r.UserCallsign, "location": r.Location,
		"id": r.ID, "eventScale": r.EventScale, "type": r.Type, "title": r.Title,
		"dateTimeDescription": r.DateTimeDescription, "status": r.Status,
	}
}

type Reports struct {
	db *store.Collection[CITrapReport]
}

func OpenReports(dataDir string) (*Reports, error) {
	db, err := store.Open[CITrapReport](filepath.Join(dataDir, "db", "citrap.jsonl"), true)
	if err != nil {
		return nil, err
	}
	return &Reports{db: db}, nil
}

func (r *Reports) Close() { r.db.Close() }

func parseWKTPoint(s string) (float64, float64) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(strings.ToUpper(s), "POINT")
	s = strings.Trim(strings.TrimSpace(s), "()")
	f := strings.Fields(s)
	if len(f) < 2 {
		return 0, 0
	}
	lon, _ := strconv.ParseFloat(f[0], 64)
	lat, _ := strconv.ParseFloat(f[1], 64)
	return lat, lon
}

const citrapMaxBytes = 64 << 20

var citrapSlots = make(chan struct{}, 2)

func (s *Server) citrapPost(w http.ResponseWriter, r *http.Request) {
	id := identityOf(r)
	clientUID := r.URL.Query().Get("clientUid")
	select {
	case citrapSlots <- struct{}{}:
		defer func() { <-citrapSlots }()
	case <-r.Context().Done():
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, citrapMaxBytes+1))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if len(body) > citrapMaxBytes {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "CI-TRAP reports are limited to 64 MB"})
		return
	}
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "report must be a zip file"})
		return
	}
	var report *xmltree.Node
	for _, f := range zr.File {
		if strings.HasSuffix(strings.ToLower(f.Name), "report.xml") {
			rc, err := f.Open()
			if err != nil {
				continue
			}
			data, _ := io.ReadAll(io.LimitReader(rc, 4<<20))
			rc.Close()
			n, err := xmltree.Parse(data)
			if err == nil && n.Name == "report" {
				report = n
			}
			break
		}
	}
	if report == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "report.xml not found in the zip"})
		return
	}
	rep := CITrapReport{
		ID: firstNonEmpty(r.PathValue("id"), report.Attr("id"), cot.NewUID()), Type: report.Attr("type"), Title: report.Attr("title"),
		UserCallsign: report.Attr("userCallsign"), UserDescription: report.Attr("userDescription"),
		DateTimeDescription: report.Attr("dateTimeDescription"), Location: report.Attr("location"),
		LocationDescription: report.Attr("locationDescription"), EventScale: report.Attr("eventScale"),
		Importance: report.Attr("importance"), Status: report.Attr("status"), Tags: report.Attr("tags"),
		ClientUID: clientUID, Groups: s.identityGroups(id),
	}
	if _, exists := s.reports.db.Get(rep.ID); exists {
		if old, ok := s.res.Get("citrap-" + rep.ID); !id.Admin && (!ok || old.Submitter != id.Name) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "only the author or an administrator can change this report"})
			return
		}
	} else if m, ok := s.missions.Get(rep.ID); ok && m.Tool != "citrap" {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "a mission with this name already exists"})
		return
	}
	rep.DateTime, _ = cot.ParseTime(report.Attr("dateTime"))
	rep.Lat, rep.Lon = parseWKTPoint(rep.Location)
	res, err := s.storeXMLResource("citrap-"+rep.ID, body, []string{"citrap"}, id.Name, "citrap", rep.Groups)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	s.res.Update(res.UID, func(x *Resource) {
		x.MIMEType = "application/zip"
		x.Name = safeFileName(firstNonEmpty(rep.Title, rep.ID)) + ".zip"
	})
	rep.Hash = res.Hash
	if err := s.reports.db.Put(rep.ID, rep); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	s.missions.db.Update(rep.ID, func(m Mission, exists bool) (Mission, bool, error) {
		if exists {
			return m, true, nil
		}
		m = Mission{Name: rep.ID, GUID: cot.NewUID(), Description: rep.Title, Tool: "citrap", Created: time.Now().UTC(), CreatorUID: clientUID,
			CreatorUser: id.Name, Groups: rep.Groups, DefaultRole: RoleSubscriber, Expiration: -1, Keywords: []string{}}
		if clientUID != "" {
			m.Subs = []MissionSub{{ClientUID: clientUID, Username: id.Name, Role: RoleOwner, Created: time.Now().UTC()}}
		}
		m.addChange(MissionChange{Type: "CREATE_MISSION", CreatorUID: clientUID})
		return m, true, nil
	})
	s.log.Info("report received", "id", rep.ID, "title", rep.Title, "by", id.Name)
	writeJSON(w, http.StatusCreated, map[string]string{"id": rep.ID})
}

func (s *Server) citrapList(w http.ResponseWriter, r *http.Request) {
	id := identityOf(r)
	q := r.URL.Query()
	kw := strings.ToLower(q.Get("keywords"))
	typ, cs := q.Get("type"), q.Get("callsign")
	var start, end time.Time
	if v := q.Get("startTime"); v != "" {
		start, _ = cot.ParseTime(v)
	}
	if v := q.Get("endTime"); v != "" {
		end, _ = cot.ParseTime(v)
	}
	maxN, _ := strconv.Atoi(q.Get("maxReportCount"))
	var box []float64
	for _, p := range strings.Split(q.Get("bbox"), ",") {
		if v, err := strconv.ParseFloat(strings.TrimSpace(p), 64); err == nil {
			box = append(box, v)
		}
	}
	out := []map[string]any{}
	reports := s.reports.db.All()
	sort.Slice(reports, func(i, j int) bool { return reports[i].DateTime.After(reports[j].DateTime) })
	for _, rep := range reports {
		if !id.Admin && len(rep.Groups) > 0 && !s.visibleTo(id, s.dir.Mask(rep.Groups)) {
			continue
		}
		if (typ != "" && !strings.EqualFold(rep.Type, typ)) || (cs != "" && !strings.EqualFold(rep.UserCallsign, cs)) {
			continue
		}
		if kw != "" && !strings.Contains(strings.ToLower(rep.Title+" "+rep.UserDescription+" "+rep.Tags), kw) {
			continue
		}
		if (!start.IsZero() && rep.DateTime.Before(start)) || (!end.IsZero() && rep.DateTime.After(end)) {
			continue
		}
		if len(box) == 4 && (rep.Lon < box[0] || rep.Lat < box[1] || rep.Lon > box[2] || rep.Lat > box[3]) {
			continue
		}
		out = append(out, rep.martiJSON())
		if maxN > 0 && len(out) >= maxN {
			break
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) citrapGet(w http.ResponseWriter, r *http.Request) {
	rep, ok := s.reports.db.Get(r.PathValue("id"))
	if !ok || (!identityOf(r).Admin && len(rep.Groups) > 0 && !s.visibleTo(identityOf(r), s.dir.Mask(rep.Groups))) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "report not found"})
		return
	}
	s.serveResource(w, r, "citrap-"+rep.ID)
}

func (s *Server) citrapDelete(w http.ResponseWriter, r *http.Request) {
	rep, ok := s.reports.db.Get(r.PathValue("id"))
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "report not found"})
		return
	}
	id := identityOf(r)
	res, _ := s.res.Get("citrap-" + rep.ID)
	if !id.Admin && res.Submitter != id.Name {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "only the author or an administrator can delete a report"})
		return
	}
	s.reports.db.Delete(rep.ID)
	s.res.Delete("citrap-" + rep.ID)
	s.missions.db.Delete(rep.ID)
	w.WriteHeader(http.StatusOK)
}

func (s *Server) citrapAttachment(w http.ResponseWriter, r *http.Request) {
	id := identityOf(r)
	q := r.URL.Query()
	reportID := firstNonEmpty(q.Get("id"), q.Get("reportId"), q.Get("missionName"))
	if reportID != "" {
		m, ok := s.missions.Get(reportID)
		if !ok || !s.missionVisible(id, m) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "report not found"})
			return
		}
		if !s.canWriteMission(r, m) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "your mission role does not allow MISSION_WRITE"})
			return
		}
	}
	res, code, err := s.storeUpload(w, r, Resource{Name: q.Get("filename"), Keywords: []string{"citrap", "attachment"}, Tool: "citrap", Submitter: id.Name,
		CreatorUID: q.Get("clientUid"), Groups: s.identityGroups(id), UID: cot.NewUID()})
	if err != nil {
		writeJSON(w, code, map[string]string{"error": err.Error()})
		return
	}
	if reportID != "" {
		if _, ok := s.missions.Get(reportID); ok {
			s.missionPutContent(reportID, res, q.Get("clientUid"))
		}
	}
	writeJSON(w, http.StatusOK, legacyMetadata(res))
}

func (s *Server) citrapRoutes(m func(string, http.HandlerFunc)) {
	m("GET /Marti/api/citrap", s.citrapList)
	m("POST /Marti/api/citrap", s.citrapPost)
	m("POST /Marti/api/citrap/attachment", s.citrapAttachment)
	m("GET /Marti/api/citrap/{id}", s.citrapGet)
	m("PUT /Marti/api/citrap/{id}", s.citrapPost)
	m("DELETE /Marti/api/citrap/{id}", s.citrapDelete)
}
