# magda-auth-arcgis

![Version: 3.0.0-pr.11.0](https://img.shields.io/badge/Version-3.0.0--pr.11.0-informational?style=flat-square)

A Magda Authentication Plugin for ArcGIS Server

## Version Compatibility

Pick the chart version that matches your Magda release:

| This chart | Requires Magda | Notes |
| ---------- | -------------- | ----- |
| **`v3.x`** (from `v3.0.0-alpha.0`) | **v7.0.0 or above** | Connects to `session-db` over **TLS** when the database enforces SSL. Uses the versioned `magda.db-client-sslmode-env-v1` Helm helper contract plus `magda.db-client-ca-env-v1` for `sslmode: verify-ca`/`verify-full` server-certificate verification (needs `magda-core` `>= 7.0.0-alpha.1`), and runs on **Node.js 22**. |
| **`v2.x`** | **v6.x or below** (v0.0.58+) | Use this line if you run **Magda v6 or lower**. Does not emit `PGSSLMODE` and will not work against an SSL-enforced external database. |

> ⚠️ **`v3.x` is a breaking change and requires Magda v7+** (on the v7 pre-release line, **`>= 7.0.0-alpha.1`**, which first shipped the `db-client-ca-env-v1` contract this chart now calls). Do **not** deploy `v3.x` alongside Magda v6 or lower, or an earlier v7 alpha — the required helper contracts are only provided by a recent enough `magda-core`, and rendering will fail closed with `no template "magda.compatibility-check" associated` or a contract-not-supported error (this is intentional — the render-time compatibility handshake is controlled by `global.magdaCompatibilityCheck`, default `true`; see the [Magda Helm Helper Contracts](https://github.com/magda-io/magda/blob/next/docs/docs/helm-helper-contracts.md) documentation).

> **Deploy as a chart dependency in the same Helm release as Magda** (not a separate `helm install`), so the `magda.compatibility-check` template resolves.

To deploy the authentication plugin with your MAGDA instance, please check [MAGDA Gateway Helm Chart Document](https://github.com/magda-io/magda/blob/master/deploy/helm/internal-charts/gateway/README.md).

### How to Use
1. Add the auth plugin as a [Helm Chart Dependency](https://helm.sh/docs/helm/helm_dependency/)
```yaml
- name: magda-auth-arcgis
  # Magda v7+: use the latest v3.x (currently pre-release). Magda v6 or lower: latest v2.x. See "Version Compatibility" above.
  version: "3.0.0-alpha.0"
  repository: "oci://ghcr.io/magda-io/charts"
```

> Since v2.0.0, we use [Github Container Registry](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry) as our official Helm Chart & Docker Image release registry.

2. Config the auth plugin with client Id:
```yaml
magda-auth-arcgis:
  arcgisClientId: xxxxxx
  arcgisInstanceBaseUrl: xxxxxx
```

3. Config Gatway to add the auth plugin to Gateway's plugin list (More details see [here](https://github.com/magda-io/magda/blob/master/deploy/helm/internal-charts/gateway/README.md))
```yaml
gateway:
  authPlugins:
  - key: "arcgis"
    baseUrl: http://magda-auth-arcgis
```

4. Create a secret `oauth-secrets` in your deployment Magda namespace with the correct value for `arcgis-client-secret` key

**Homepage:** <https://github.com/magda-io/magda-auth-arcgis>

## Source Code

* <https://github.com/magda-io/magda-auth-arcgis>

## Requirements

Kubernetes: `>= 1.14.0-0`

| Repository | Name | Version |
|------------|------|---------|
| oci://ghcr.io/magda-io/charts | magda-common | 7.0.0-alpha.1 |

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| arcgisClientId | string | `""` | ArcGIS Client ID |
| arcgisInstanceBaseUrl | string | `""` | ArcGIS Server Base URL e.g. "https://www.arcgis.com" |
| authPluginConfig.authenticationMethod | string | `"IDP-URI-REDIRECTION"` | The authentication method of the plugin. Support values are: <ul> <li>`IDP-URI-REDIRECTION`: the plugin will rediredct user agent to idp (identity provider) for authentication. e.g. Google & fackebook oauth etc.</li> <li>`PASSWORD`: the plugin expect frontend do a form post that contains username & password to the plugin for authentication.</li> <li>`QR-CODE`: the plugin offers a url that is used by the frontend to request auth challenge data. The data will be encoded into a QR-code image and expect the user scan the QR code with a mobile app to complete the authentication request.</li> </ul> See [Authentication Plugin Specification](https://github.com/magda-io/magda/blob/master/docs/docs/authentication-plugin-spec.md) for more details |
| authPluginConfig.iconUrl | string | `"/icon.svg"` | the display icon URL of the auth plugin. |
| authPluginConfig.key | string | `"arcgis"` | the unique key of the auth plugin. Allowed characters: [a-zA-Z0-9\-] |
| authPluginConfig.loginFormExtraInfoContent | string | `""` | Optional; Only applicable when authenticationMethod = "PASSWORD". If present, will displayed the content underneath the login form to provide extra info to users. e.g. how to reset password Can support content in markdown format. |
| authPluginConfig.loginFormExtraInfoHeading | string | `""` | Optional; Only applicable when authenticationMethod = "PASSWORD". If present, will displayed the heading underneath the login form to provide extra info to users. e.g. how to reset password |
| authPluginConfig.loginFormPasswordFieldLabel | string | "Password" | Optional; Only applicable when authenticationMethod = "PASSWORD". |
| authPluginConfig.loginFormUsernameFieldLabel | string | "Username" | Optional; Only applicable when authenticationMethod = "PASSWORD". |
| authPluginConfig.name | string | `"ArcGIS"` | the display name of the auth plugin. |
| authPluginConfig.qrCodeAuthResultPollUrl | string | `""` | Only applicable & compulsory when authenticationMethod = "QR-CODE". The url that is used by frontend to poll the authentication processing result. See [Authentication Plugin Specification](https://github.com/magda-io/magda/blob/master/docs/docs/authentication-plugin-spec.md) for more details |
| authPluginConfig.qrCodeExtraInfoContent | string | `""` | Only applicable & compulsory when authenticationMethod = "QR-CODE". If present, will displayed the content underneath the login form to provide extra info to users. e.g. how to download moile app to scan the QR Code. Can support content in markdown format. |
| authPluginConfig.qrCodeExtraInfoHeading | string | `""` | Only applicable & compulsory when authenticationMethod = "QR-CODE". If present, will displayed the heading underneath the QR Code image to provide extra instruction to users. e.g. how to download moile app to scan the QR Code |
| authPluginConfig.qrCodeImgDataRequestUrl | string | `""` | Only applicable & compulsory when authenticationMethod = "QR-CODE". The url that is used by frontend client to request auth challenge data from the authentication plugin. See [Authentication Plugin Specification](https://github.com/magda-io/magda/blob/master/docs/docs/authentication-plugin-spec.md) for more details |
| authPluginRedirectUrl | string | `nil` | the redirection url after the whole authentication process is completed. Authentication Plugins will use this value as default. The following query paramaters can be used to supply the authentication result: <ul> <li>result: (string) Compulsory. Possible value: "success" or "failure". </li> <li>errorMessage: (string) Optional. Text message to provide more information on the error to the user. </li> </ul> This field is for overriding the value set by `global.authPluginRedirectUrl`. Unless you want to have a different value only for this auth plugin, you shouldn't set this value. |
| autoscaler.enabled | bool | `false` | turn on the autoscaler or not |
| autoscaler.maxReplicas | int | `3` |  |
| autoscaler.minReplicas | int | `1` |  |
| autoscaler.targetCPUUtilizationPercentage | int | `80` |  |
| defaultAdminUserId | string | `"00000000-0000-4000-8000-000000000000"` | which system account we used to talk to auth api The value of this field will only be used when `global.defaultAdminUserId` has no value |
| defaultImage.imagePullSecret | bool | `false` |  |
| defaultImage.pullPolicy | string | `"IfNotPresent"` |  |
| defaultImage.repository | string | `"ghcr.io/magda-io"` |  |
| esriOrgGroup | string | `""` | Optional; ArcGIS Org Group |
| global | object | `{"authPluginAllowedExternalRedirectDomains":[],"authPluginRedirectUrl":"/sign-in-redirect","externalUrl":"","image":{},"magdaCompatibilityCheck":true,"rollingUpdate":{}}` | only for providing appropriate default value for helm lint |
| global.authPluginAllowedExternalRedirectDomains | list | `[]` | By default, at end of authentication process, an auth plugin will never redirect the user to an external domain,  even if `authPluginRedirectUrl` is configured to an URL with an external domain. Unless an external domain is added to the whitelist i.e. this `authPluginAllowedExternalRedirectDomains` config,  any auth plugins will always ignore the domain part of the url (if supplied) and only redirect the user to the URL path under the current domain. Please note: you add a url host string to this list. e.g. "abc.com:8080" |
| global.magdaCompatibilityCheck | bool | `true` | Whether to run the Magda Helm helper-contract compatibility check. Leave as `true` in normal deployments alongside Magda v7+; set to `false` (unquoted) only for a standalone `helm template`/`helm lint` (no magda-core). See https://github.com/magda-io/magda/blob/next/docs/docs/helm-helper-contracts.md |
| image.name | string | `"magda-auth-arcgis"` |  |
| replicas | int | `1` | no. of initial replicas |
| resources.limits.cpu | string | `"50m"` |  |
| resources.requests.cpu | string | `"10m"` |  |
| resources.requests.memory | string | `"30Mi"` |  |
