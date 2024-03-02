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
