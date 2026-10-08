# 3.0.0

- Enforce TLS on the `session-db` connection when deployed against an enforced-SSL database (magda-io/magda#3742):
  - Upgrade `@magda/authentication-plugin-sdk` + the `magda-common` Helm chart dependency to v7 (`7.0.0`), and include the `magda.db-client-sslmode-env-v1` helper contract so the pod receives `PGSSLMODE`. The v7 SDK derives the `node-postgres` `ssl` option from `PGSSLMODE`/`PGSSLROOTCERT` explicitly.
  - Support `sslmode: verify-ca`/`verify-full` via the `magda.db-client-ca-env-v1` helper contract (mount the server CA + set `PGSSLROOTCERT`). Self-guarded under `disable`/`require`.
  - Add `global.magdaCompatibilityCheck` (default `true`); the `helm-lint` script sets it `false` for the standalone render.
- Modernize the toolchain: build as an **ES module**, upgrade to **Node.js 22**, TypeScript 5, `tsx`/mocha 10, `@magda/docker-utils` v5, and `passport` 0.7. Add the `set-version` CI workflow.
- **Requires Magda v7.0.0 or above** (breaking change). Deploy as a chart dependency in the same Helm release as Magda. Users on Magda v6 or lower should stay on the `2.x` line.

# 2.0.1

- deployment auto roll based on config
- add support to allowedExternalRedirectDomains config options

# 2.0.0

-   Upgrade nodejs to version 14
-   Upgrade other dependencies
-   Release all artifacts to GitHub Container Registry (instead of docker.io & https://charts.magda.io)
-   Upgrade magda-common chart version to v2.1.1
-   Build multi-arch docker images

# v1.2.3

- Upgrade to magda-common lib chart v1.0.0-alpha.4
- Use named templates from magda-common lib chart for docker image related logic

# v1.2.2

- Will not check & use global image config anymore. Only magda core repo modules / charts will check & use global image config. 

# v1.2.1

- Use library chart "magda-common" & fix Magda v1 deployment issue on the first deployment

# v1.2.0

- Change the way of locate session-db secret to be compatible with Magda v1 (still backwards compatible with earlier versions)
- Avoid using .Chart.Name for image name --- it will change when use chart dependency alias