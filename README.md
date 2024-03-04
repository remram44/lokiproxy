Loki proxy
==========

This is a proxy for Grafana Loki that can validate and rewrite queries based on the client's identity. I use it to add namespace selectors to queries from my Kubernetes cluster's users.

For example, when john sends this query:

```logql
{controller="myapp"} |= "fatal error"
```

I look up their OIDC identity, find out their namespaces are "reprostudy" and "largeanalysis", and send this query to Loki instead:

```logql
{controller="myapp", namespace=~"reprostudy|largeanalysis"} |= "fatal error"
```

This allows for multitenancy of my logging system without splitting logs between different Loki tenants, as that would prevent operators from querying across namespaces easily.

## How to use

The proxy is controlled by a file which specifies which labels (in LogQL syntax) are required for which users (OIDC subject). Lines starting with a `#` are ignored. For example:

```plain
# Remi has access to two job values
http://cilogon.org/serverA/users/12345
  job=~"kubernetes-audit|kubernetes-pods"
# Vicky has access to specific pod logs
http://cilogon.org/serverA/users/34567
  job="kubernetes-pods"
  namespace=~"reproducibility|taguette"
# Rob has access to all but audit logs
http://cilogon.org/serverA/users/56789
  job!="kubernetes-audit
```

The server itself is configured with environment variables:

* Upstream configuration, i.e. how to connect to the Loki server:
    * `LOKIPROXY_UPSTREAM_URL`: URL of Loki, for example `https://loki.example.org:3100`. Required.
    * `LOKIPROXY_UPSTREAM_CA`: path to custom CA certificate to validate Loki's certificate. Optional, defaults to system certificate store.
    * `LOKIPROXY_UPSTREAM_CERT` and `LOKIPROXY_UPSTREAM_KEY`: path to client certificate used to authenticate with Loki (mTLS). Optional, defaults to not presenting a client certificate.
* Frontend configuration, i.e. how to accept connections from clients (for example Grafana):
    * `LOKIPROXY_LISTEN_ADDR`: address and port on which to listen for client connections. Can specify a bind address or not, for example `:3100` or `127.0.0.1:443`. Required.
    * `LOKIPROXY_FRONTEND_CERT` and `LOKIPROXY_FRONTEND_KEY`: path to server certificate. Setting this enables TLS. Optional, defaults to plaintext.
    * `LOKIPROXY_FRONTEND_CA`: path to CA certificate to validate client certificates. Setting this enables mTLS. Requires frontend certificate and key. Optional, defaults to not requiring client certificates.
* OIDC configuration, i.e. how to authenticate user requests:
    * `LOKIPROXY_OIDC_PROVIDER`: OpenID Connect provider URL, used to check the ID tokens provided by clients. Needs to match exactly. For example `https://myorg.us.auth0.com/`. Required.
    * `LOKIPROXY_OIDC_CLIENT_ID`: OpenID Connect client ID. The secret is NOT required to authenticate ID tokens. Required.
* Access configuration, i.e. how to validate and transform requests:
    * `LOKIPROXY_IDENTITY_MAP_FILE`: path to the file mapping OIDC identities to required LogQL label selectors. Required.
* Other settings
    * `LOKIPROXY_ALLOW_ALERTS`: boolean, whether to allow queries for alerts, which don't come with an ID token. Make sure users can't reach the proxy if enabling this, or they can bypass access control by pretending to be an alert rule (for example, use mTLS). Optional, defaults to disallowing alert queries.
