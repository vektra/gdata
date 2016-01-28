package gdata

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/bmizerany/pat"
	consul "github.com/hashicorp/consul/api"
)

type Server struct {
	mux *pat.PatternServeMux
	con *consul.Client
}

func NewServer() (*Server, error) {

	cfg := consul.DefaultConfig()

	con, err := consul.NewClient(cfg)
	if err != nil {
		return nil, err
	}

	s := &Server{
		mux: pat.New(),
		con: con,
	}

	s.mux.Post("/:org/:type/:id", http.HandlerFunc(s.set))

	s.mux.Get("/:org/:type/_search", http.HandlerFunc(s.search))
	s.mux.Get("/:org/:type/:id", http.HandlerFunc(s.get))

	return s, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	s.mux.ServeHTTP(w, req)
}

func (s *Server) key(org, typ, id string) string {
	return fmt.Sprintf("%s-%s-%s", org, typ, id)
}

func (s *Server) keyType(org, typ string) string {
	return fmt.Sprintf("%s-%s", org, typ)
}

func (s *Server) set(w http.ResponseWriter, req *http.Request) {
	var (
		org = req.URL.Query().Get(":org")
		typ = req.URL.Query().Get(":type")
		id  = req.URL.Query().Get(":id")
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

func (s *Server) extractId(key string) string {
	parts := strings.Split(key, "-")
	return parts[2]
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
