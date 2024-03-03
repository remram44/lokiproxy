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
