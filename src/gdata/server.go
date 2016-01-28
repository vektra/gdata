package gdata

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/bmizerany/pat"
	consul "github.com/hashicorp/consul/api"
	"github.com/satori/go.uuid"
	"github.com/vektra/jwt-go"
)

type Server struct {
	cfg *Config
	mux *pat.PatternServeMux
	con *consul.Client
}

func NewServer(cfg *Config) (*Server, error) {
	concfg := consul.DefaultConfig()

	con, err := consul.NewClient(concfg)
	if err != nil {
		return nil, err
	}

	if cfg.key == nil {
		return nil, fmt.Errorf("Config needs to contain a key")
	}

	s := &Server{
		cfg: cfg,
		mux: pat.New(),
		con: con,
	}

	s.mux.Post("/create", http.HandlerFunc(s.create))
	s.mux.Post("/token", s.extractOrg(http.HandlerFunc(s.newToken)))

	s.mux.Post("/dir/:type/:id", s.extractOrg(http.HandlerFunc(s.set)))
	s.mux.Post("/dir/:type", s.extractOrg(http.HandlerFunc(s.setGenId)))

	s.mux.Get("/dir/:type/_search", s.extractOrg(http.HandlerFunc(s.search)))
	s.mux.Get("/dir/:type/:id", s.extractOrg(http.HandlerFunc(s.get)))

	return s, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	s.mux.ServeHTTP(w, req)
}

func (s *Server) key(org, typ, id string) string {
	return fmt.Sprintf("%s/%s", s.keyType(org, typ), id)
}

func (s *Server) keyType(org, typ string) string {
	return fmt.Sprintf("data/%s/%s", org, typ)
}

func (s *Server) extractId(key string) string {
	parts := strings.Split(key, "/")
	return parts[3]
}

func (s *Server) extractOrg(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		token, err := jwt.ParseFromRequest(req,
			func(*jwt.Token) (interface{}, error) { return &s.cfg.key.PublicKey, nil })
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}

		params := make(url.Values)

		params.Add(":org", token.Claims["sub"].(string))

		req.URL.RawQuery = params.Encode() + "&" + req.URL.RawQuery

		h.ServeHTTP(w, req)
	})
}

func randomId() string {
	u := uuid.NewV4()
	return strings.TrimRight(base64.URLEncoding.EncodeToString(u.Bytes()), "=")
}

func (s *Server) create(w http.ResponseWriter, req *http.Request) {
	org := randomId()

	token := jwt.New(jwt.SigningMethodES256)
	token.Claims["sub"] = org

	str, err := token.SignedString(s.cfg.key)
	if err != nil {
		http.Error(w, "error signing token", 500)
		return
	}

	w.Write([]byte(str))
}

func (s *Server) newToken(w http.ResponseWriter, req *http.Request) {
	var (
		org = req.URL.Query().Get(":org")
	)

	token := jwt.New(jwt.SigningMethodES256)
	token.Claims["sub"] = org

	str, err := token.SignedString(s.cfg.key)
	if err != nil {
		http.Error(w, "error signing token", 500)
		return
	}

	w.Write([]byte(str))
}

func (s *Server) setGenId(w http.ResponseWriter, req *http.Request) {
	id := randomId()

	s.setId(w, req, id)
}

func (s *Server) set(w http.ResponseWriter, req *http.Request) {
	id := req.URL.Query().Get(":id")

	s.setId(w, req, id)
}

func (s *Server) setId(w http.ResponseWriter, req *http.Request, id string) {
	var (
		org = req.URL.Query().Get(":org")
		typ = req.URL.Query().Get(":type")
	)

	defer req.Body.Close()

	data, err := ioutil.ReadAll(req.Body)
	if err != nil {
		http.Error(w, "unable to read data to write", 400)
		return
	}

	if len(data) == 0 {
		http.Error(w, "misformed json: none presented", 400)
	}

	var buf bytes.Buffer

	err = json.Compact(&buf, data)
	if err != nil {
		http.Error(w, fmt.Sprintf("misformed json: %s", err), 400)
		return
	}

	if buf.String()[0] != '{' {
		http.Error(w, "misformed json: toplevel must be an object", 400)
		return
	}

	kv := &consul.KVPair{
		Key:   s.key(org, typ, id),
		Value: buf.Bytes(),
	}

	_, err = s.con.KV().Put(kv, nil)
	if err != nil {
		http.Error(w, "error writing value", 500)
	}
}

func (s *Server) get(w http.ResponseWriter, req *http.Request) {
	var (
		org = req.URL.Query().Get(":org")
		typ = req.URL.Query().Get(":type")
		id  = req.URL.Query().Get(":id")
	)

	defer req.Body.Close()

	opts := &consul.QueryOptions{
		RequireConsistent: true,
		AllowStale:        false,
	}

	kv, _, err := s.con.KV().Get(s.key(org, typ, id), opts)
	if err != nil {
		http.Error(w, "error writing value", 500)
		return
	}

	w.Write(kv.Value)
}

type Query struct {
	key   string
	value string
}

func (s *Server) parseQuery(q string) (*Query, error) {
	idx := strings.IndexByte(q, ':')
	if idx == -1 {
		return nil, fmt.Errorf("Invalid query: %s", q)
	}

	return &Query{
		key:   q[:idx],
		value: q[idx+1:],
	}, nil
}

func (q *Query) Match(kv *consul.KVPair) bool {
	obj := make(map[string]interface{})

	err := json.Unmarshal(kv.Value, &obj)
	if err != nil {
		return false
	}

	val, ok := obj[q.key]
	if !ok {
		return false
	}

	str, ok := val.(string)
	if !ok {
		return false
	}

	return str == q.value
}

func (s *Server) search(w http.ResponseWriter, req *http.Request) {
	var (
		org = req.URL.Query().Get(":org")
		typ = req.URL.Query().Get(":type")
		q   = req.URL.Query().Get("q")
	)

	defer req.Body.Close()

	query, err := s.parseQuery(q)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	opts := &consul.QueryOptions{
		RequireConsistent: true,
		AllowStale:        false,
	}

	pairs, _, err := s.con.KV().List(s.keyType(org, typ), opts)
	if err != nil {
		http.Error(w, "error writing value", 500)
		return
	}

	type hit struct {
		Id    string           `json:"id"`
		Value *json.RawMessage `json:"value"`
	}

	var results []hit

	for _, kv := range pairs {
		if query.Match(kv) {
			var raw json.RawMessage
			raw = kv.Value

			results = append(results, hit{
				Id:    s.extractId(kv.Key),
				Value: &raw,
			})
		}
	}

	json.NewEncoder(w).Encode(results)
}
