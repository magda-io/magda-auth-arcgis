# E2E Test Case: session-db TLS (incl. `verify-full`) — Magda v7

Verifies that this plugin (v3, ESM / Node 22 / SDK v7) connects to `session-db`
over **TLS** when deployed alongside **Magda v7**, including `sslmode: verify-full`
server-certificate verification via the `magda.db-client-ca-env-v1` contract —
run against a real cluster (e.g. minikube).

The ArcGIS OAuth login itself is not exercised here: the provider-specific
`passport-arcgis` flow needs a real ArcGIS instance and cannot be mocked as a
standard OIDC provider. The plugin's **only** `session-db` code is the SDK's
session store (`createMagdaSessionRouter`), which is what this case drives — the
same code path a real login uses.

## Setup

Deploy Magda v7 + this plugin in **one** Helm release (so the helper-contract
compatibility check resolves), with `verify-full` + a CA secret. For an
**in-cluster** combined-db, use the DB's own generated CA (its SANs already
cover `session-db`):

```bash
DBPOD=$(kubectl get pod -n magda -l app.kubernetes.io/name=combined-db-postgresql-pg17 -o name | head -1)
kubectl exec -n magda "$DBPOD" -c postgresql -- cat /opt/bitnami/postgresql/certs/ca.crt > /tmp/pg-ca.crt
kubectl create secret generic pg-ca -n magda --from-file=ca.crt=/tmp/pg-ca.crt

# umbrella/values.yaml:
#   global:
#     magdaCompatibilityCheck: true
#     postgresql: { client: { sslmode: verify-full, sslRootCertSecret: { name: pg-ca, key: ca.crt } } }
#   magda-auth-arcgis:
#     arcgisClientId: "e2e-fake-arcgis-client"
#     arcgisInstanceBaseUrl: "https://www.arcgis.com"
#     image: { tag: "<PLUGIN_VERSION>" }
#   magda: { magda-core: { gateway: { authPlugins: [ { key: arcgis, baseUrl: http://magda-auth-arcgis } ] } } }

# the plugin needs oauth-secrets/arcgis-client-secret:
kubectl create secret generic oauth-secrets -n magda --from-literal=arcgis-client-secret=e2e-fake
helm upgrade magda . -n magda --wait
```

## Assertions

### A. Pod healthy + CA delivered

```bash
kubectl logs -n magda deploy/magda-auth-arcgis | tail -3          # "Listening on port 80"
kubectl get deploy magda-auth-arcgis -n magda \
  -o jsonpath='{range .spec.template.spec.containers[0].env[*]}{.name}={.value}{"\n"}{end}' | grep PGSSL
# PGSSLMODE=verify-full
# PGSSLROOTCERT=/etc/magda/postgresql-ca/root.crt
kubectl exec -n magda deploy/magda-auth-arcgis -- ls /etc/magda/postgresql-ca/root.crt
```

### B. The SDK reads + writes `session-db` under verify-full

```bash
DBPOD=$(kubectl get pod -n magda -l app.kubernetes.io/name=combined-db-postgresql-pg17 -o name | head -1)
before=$(kubectl exec -n magda "$DBPOD" -c postgresql -- bash -c 'PGPASSWORD=$(cat $POSTGRES_PASSWORD_FILE) psql -U postgres -d session -tAc "SELECT count(*) FROM session;"')
kubectl exec -n magda deploy/magda-auth-arcgis -- node --input-type=module -e '
import express from "express"; import http from "http";
import { createMagdaSessionRouter } from "@magda/authentication-plugin-sdk";
const app=express();
app.use(createMagdaSessionRouter({sessionSecret:"e2e",sessionDBHost:"session-db",sessionDBPort:5432}));
app.get("/w",(req,res)=>{req.session.e2e="arcgis-vf-"+Date.now();res.end("ok");});
const s=app.listen(0,()=>{const p=s.address().port;http.get("http://127.0.0.1:"+p+"/w",r=>{r.on("data",()=>{});r.on("end",()=>setTimeout(()=>{console.log("SDK write status "+r.statusCode);s.close();process.exit(0);},2000));});});'
after=$(kubectl exec -n magda "$DBPOD" -c postgresql -- bash -c 'PGPASSWORD=$(cat $POSTGRES_PASSWORD_FILE) psql -U postgres -d session -tAc "SELECT count(*) FROM session;"')
echo "session rows: $before -> $after"      # increases by one

IP=$(kubectl get pod -n magda -l service=magda-auth-arcgis --field-selector=status.phase=Running -o jsonpath='{.items[0].status.podIP}')
kubectl exec -n magda "$DBPOD" -c postgresql -- bash -c \
  "PGPASSWORD=\$(cat \$POSTGRES_PASSWORD_FILE) psql -U postgres -tAc \"
     SELECT a.datname,a.usename,s.ssl,s.version FROM pg_stat_ssl s JOIN pg_stat_activity a USING (pid)
     WHERE host(a.client_addr)='$IP';\""
# -> session|client|t|TLSv1.3
```

### C. The CA is actually *verified* (not just present) — negative control

Prove the connection succeeds only because the delivered CA verifies the server
certificate: with the CA it connects; without it (or with a wrong CA) it fails.

```bash
# WITH the delivered CA -> verifies + connects
kubectl exec -n magda deploy/magda-auth-arcgis -- node --input-type=module -e '
import pg from "pg"; import fs from "fs";
const ca = fs.readFileSync(process.env.PGSSLROOTCERT, "utf-8");
const pool = new pg.Pool({ host:"session-db", port:5432, database:"session", ssl:{ rejectUnauthorized:true, ca } });
const r = await pool.query("SELECT s.ssl, s.version FROM pg_stat_ssl s WHERE pid=pg_backend_pid()");
console.log("with CA   -> ssl="+r.rows[0].ssl+" "+r.rows[0].version); await pool.end();'
# with CA   -> ssl=true TLSv1.3

# WITHOUT the CA (same verify-full) -> MUST fail
kubectl exec -n magda deploy/magda-auth-arcgis -- node --input-type=module -e '
import pg from "pg";
const pool = new pg.Pool({ host:"session-db", port:5432, database:"session", ssl:{ rejectUnauthorized:true } });
try { await pool.query("SELECT 1"); console.log("no CA -> CONNECTED (unexpected!)"); }
catch(e){ console.log("no CA -> FAILED ->", e.code||e.message); } await pool.end().catch(()=>{});'
# no CA -> FAILED -> UNABLE_TO_VERIFY_LEAF_SIGNATURE
```

This is the difference between `require` (encrypt only) and `verify-*` (encrypt
**and** validate the certificate): under `verify-full` the connection is refused
unless the CA delivered by the `magda.db-client-ca-env-v1` contract matches the
server's issuer.

## Result

Verified on minikube with Magda `7.0.0-alpha.1` and the plugin `3.0.0-pr.11.0`:
the modernized ESM pod starts (`Listening on port 80`), receives the CA under
`verify-full`, and the SDK session store connects + writes over the verified TLS
connection (`ssl = t`, `TLSv1.3`). The negative control confirms the CA is
actually validated — the same `verify-full` connection fails with
`UNABLE_TO_VERIFY_LEAF_SIGNATURE` when the CA is absent or wrong.

## Cleanup

```bash
kubectl delete secret pg-ca oauth-secrets -n magda
# then uninstall the release + namespace as usual
```
