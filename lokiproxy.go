package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"

	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/remram44/lokiproxy/internal/parser"
)

// GET /loki/api/v1/query
//   query params to change: query
//   query params to pass: limit, time, direction
// GET /loki/api/v1/query_range
//   query params to change: query
//   query params to pass: limit, start, end, since, step, interval, direction
// GET /loki/api/v1/series
//   query params to change: match[]
//   query params to pass: start, end, since
//   can be POST form-urlencoded
// GET /loki/api/v1/tail
//   query params to change: query
//   query params to pass: delay_for, limit, start
// GET /loki/api/v1/labels
//   query params to pass: start, end, since
// GET /loki/api/v1/label/<name>/values
//   block?

var proxyClient *http.Client
var lokiUrl url.URL
var oidcVerifier *oidc.IDTokenVerifier

func main() {
	proxyClient = &http.Client{}

	// Read upstream URL
	{
		arg := os.Getenv("LOKIPROXY_UPSTREAM_URL")
		if arg == "" {
			log.Fatalf("LOKIPROXY_UPSTREAM_URL is not set")
		}
		r, err := url.Parse(arg)
		if err != nil {
			log.Fatalf("can't parse Loki upstream URL: %s", err)
		}
		lokiUrl = *r
	}

	// Read TLS configuration
	{
		var rootCAs *x509.CertPool
		argCA := os.Getenv("LOKIPROXY_CA")
		if argCA != "" {
			pem, err := os.ReadFile(argCA)
			if err != nil {
				log.Fatalf("can't open CA certificate bundle: %s", err)
			}
			rootCAs = x509.NewCertPool()
			rootCAs.AppendCertsFromPEM(pem)
		}

		var certificates []tls.Certificate
		argCert := os.Getenv("LOKIPROXY_CERT")
		argKey := os.Getenv("LOKIPROXY_KEY")
		if argCert != "" || argKey != "" {
			cert, err := tls.LoadX509KeyPair(argCert, argKey)
			if err != nil {
				log.Fatalf("can't load client certificate: %s", err)
			}
			certificates = []tls.Certificate{cert}
		}

		proxyClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: certificates,
				RootCAs:      rootCAs,
			},
		}
	}

	// Create OIDC verifier
	{
		argProvider := os.Getenv("LOKIPROXY_OIDC_PROVIDER")
		if argProvider == "" {
			log.Fatalf("LOKIPROXY_OIDC_PROVIDER is not set")
		}
		argClientID := os.Getenv("LOKIPROXY_OIDC_CLIENT_ID")
		if argClientID == "" {
			log.Fatalf("LOKIPROXY_OIDC_CLIENT_ID is not set")
		}
		provider, err := oidc.NewProvider(context.TODO(), argProvider)
		if err != nil {
			log.Fatalf("can't create OIDC provider: %s", err)
		}
		oidcVerifier = provider.Verifier(&oidc.Config{ClientID: argClientID})
	}

	// Read listen address
	listenAddr := os.Getenv("LOKIPROXY_LISTEN_ADDR")
	if listenAddr == "" {
		log.Fatalf("LOKIPROXY_LISTEN_ADDR is not set")
	}

	// Set up routes
	mux := http.NewServeMux()
	mux.HandleFunc("/loki/api/v1/query", handleQuery)
	mux.HandleFunc("/loki/api/v1/query_range", handleQueryRange)
	mux.HandleFunc("/loki/api/v1/series", handleSeries)
	mux.HandleFunc("/loki/api/v1/tail", handleTail)
	mux.HandleFunc("/loki/api/v1/labels", handleLabels)
	mux.HandleFunc("/loki/api/v1/label/{label}/values", handleLabelValues)

	// Create HTTP server
	server := http.Server{
		Addr:    listenAddr,
		Handler: mux,
	}
	log.Printf("Listening on %s", listenAddr)
	log.Fatal(server.ListenAndServe())
}

func sendError(res http.ResponseWriter, message string) {
	res.WriteHeader(400)
	io.WriteString(res, message)
}

func makeProxyUrl(path string) url.URL {
	r := lokiUrl
	r.Path = path
	return r
}

func getNamespacesForUser(res http.ResponseWriter, req *http.Request) (map[string]interface{}, bool) {
	// Get user identity
	idTokens := req.Header["X-Id-Token"]
	if idTokens == nil || len(idTokens) != 1 {
		res.WriteHeader(410)
		io.WriteString(res, "missing ID token")
		return nil, false
	}
	idToken, err := oidcVerifier.Verify(req.Context(), idTokens[0])
	if err != nil {
		log.Print("invalid ID token")
		res.WriteHeader(410)
		io.WriteString(res, "invalid ID token")
		return nil, false
	}
	log.Printf("id token: %#v", idToken.Subject)

	// TODO: Get allowed namespaces for user
	allowedNamespaces := make(map[string]interface{})

	return allowedNamespaces, true
}

func respondWithProxy(
	path string,
	req *http.Request,
	res http.ResponseWriter,
	setArgs map[string][]string,
	passthroughArgs []string,
	ctx context.Context,
) {
	// Assemble query parameters
	origQuery := req.URL.Query()
	proxyQuery := make(url.Values)
	for _, key := range passthroughArgs {
		values, ok := origQuery[key]
		if ok {
			proxyQuery[key] = values
		}
	}
	for key, values := range setArgs {
		proxyQuery[key] = values
	}

	// Do request
	proxyUrl := makeProxyUrl(path)
	proxyUrl.RawQuery = proxyQuery.Encode()
	proxyReq, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		proxyUrl.String(),
		nil,
	)
	if err != nil {
		res.WriteHeader(500)
		io.WriteString(res, "internal error")
		log.Printf("error creating proxy request: %s", err)
		return
	}
	proxyRes, err := proxyClient.Do(proxyReq)
	if err != nil {
		res.WriteHeader(503)
		io.WriteString(res, "internal error")
		log.Printf("error sending proxy request: %s", err)
		return
	}

	// Send response
	res.Header()["Content-Type"] = proxyRes.Header["Content-Type"]
	res.WriteHeader(proxyRes.StatusCode)
	io.Copy(res, proxyRes.Body)
}

func handleQuery(res http.ResponseWriter, req *http.Request) {
	if req.Method == "GET" {
		args := req.URL.Query()
		if len(args["query"]) != 1 {
			sendError(res, "one query expected")
			return
		}
		query := args["query"][0]

		// Find user, get allowed namespaces
		allowedNamespaces, ok := getNamespacesForUser(res, req)
		if !ok {
			return
		}

		// Rewrite query
		query = parser.ProcessQuery(query, allowedNamespaces)

		// Proxy
		respondWithProxy(
			"/loki/api/v1/query",
			req,
			res,
			map[string][]string{"query": []string{query}},
			[]string{"limit", "time", "direction"},
			req.Context(),
		)
	} else {
		log.Printf("got %s to query", req.Method)
		sendError(res, "use method GET")
	}
}

func handleQueryRange(res http.ResponseWriter, req *http.Request) {
	if req.Method == "GET" {
		args := req.URL.Query()
		if len(args["query"]) != 1 {
			sendError(res, "one query expected")
			return
		}
		query := args["query"][0]

		// Find user, get allowed namespaces
		allowedNamespaces, ok := getNamespacesForUser(res, req)
		if !ok {
			return
		}

		// Rewrite query
		query = parser.ProcessQuery(query, allowedNamespaces)

		// Proxy
		respondWithProxy(
			"/loki/api/v1/query_range",
			req,
			res,
			map[string][]string{"query": []string{query}},
			[]string{"limit", "start", "end", "since", "step", "interval", "direction"},
			req.Context(),
		)
	} else {
		log.Printf("got %s to query_range", req.Method)
		sendError(res, "use method GET")
	}
}

func handleSeries(res http.ResponseWriter, req *http.Request) {
	if req.Method == "GET" {
		args := req.URL.Query()
		queries := args["match[]"]

		// Find user, get allowed namespaces
		allowedNamespaces, ok := getNamespacesForUser(res, req)
		if !ok {
			return
		}

		// Rewrite query
		for key := range queries {
			queries[key] = parser.ProcessQuery(queries[key], allowedNamespaces)
		}

		// Proxy
		respondWithProxy(
			"/loki/api/v1/series",
			req,
			res,
			map[string][]string{"query": queries},
			[]string{"limit", "start", "end", "since", "step", "interval", "direction"},
			req.Context(),
		)
	} else if req.Method == "POST" {
		// TODO
		sendError(res, "not yet implemented")
	} else {
		log.Printf("got %s to series", req.Method)
		sendError(res, "use method GET")
	}
}

func handleTail(res http.ResponseWriter, req *http.Request) {
	if req.Method == "GET" {
		args := req.URL.Query()
		if len(args["query"]) != 1 {
			sendError(res, "one query expected")
			return
		}
		query := args["query"][0]

		// Find user, get allowed namespaces
		allowedNamespaces, ok := getNamespacesForUser(res, req)
		if !ok {
			return
		}

		// Rewrite query
		query = parser.ProcessQuery(query, allowedNamespaces)

		// Proxy
		respondWithProxy(
			"/loki/api/v1/tail",
			req,
			res,
			map[string][]string{"query": []string{query}},
			[]string{"delay_for", "limit", "start"},
			req.Context(),
		)
	} else {
		log.Printf("got %s to tail", req.Method)
		sendError(res, "use method GET")
	}
}

func handleLabels(res http.ResponseWriter, req *http.Request) {
	if req.Method == "GET" {
		// Proxy
		respondWithProxy(
			"/loki/api/v1/labels",
			req,
			res,
			map[string][]string{},
			[]string{"start", "end", "since"},
			req.Context(),
		)
	} else {
		log.Printf("got %s to labels", req.Method)
		sendError(res, "use method GET")
	}
}

func handleLabelValues(res http.ResponseWriter, _ *http.Request) {
	res.WriteHeader(403)
	io.WriteString(res, "label values API is disabled")
}
