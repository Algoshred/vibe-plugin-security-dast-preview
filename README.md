## @vibecontrols/vibe-plugin-security-dast-preview

OWASP ZAP baseline DAST provider for the `deploy.preview` lifecycle stage in [VibeControls](https://vibecontrols.com). Provider name: `zap-baseline`. Wraps the `ghcr.io/zaproxy/zaproxy:stable` Docker image and runs `zap-baseline.py` against the preview URL.

Registers itself with [`@vibecontrols/vibe-plugin-security`](https://www.npmjs.com/package/@vibecontrols/vibe-plugin-security) under the per-stage provider type `security.release` (per `PROVIDER_TYPE_FOR_STAGE("deploy.preview")`). When the user picks "zap-baseline" as their default provider for `deploy.preview`, the security meta plugin dispatches scan runs here.

## Install

```bash
vibe plugin install @vibecontrols/vibe-plugin-security-dast-preview
vibe security providers set-default --stage deploy.preview --provider zap-baseline
```

This plugin does NOT download a binary — it shells out to Docker. On `ensureToolInstalled()` the plugin probes `docker info` and best-effort `docker pull ghcr.io/zaproxy/zaproxy:stable` so the first real scan starts fast. If Docker is missing or unreachable, every scan returns a "succeeded" result with a single info finding describing the skip reason — the lifecycle never blocks on local-tooling absence.

## Behavior

- **Probes** `docker info` (5s timeout). On failure, emits info finding `tool.docker.unavailable` with reason `docker-missing` and skips.
- **HEAD-probes** `previewUrl` (10s timeout). On missing/failed probe, emits info finding `target.url.unreachable` with reason `target-url-missing` or `target-url-unreachable`.
- **Runs**:
  ```
  docker run --rm -v <workdir>:/zap/wrk/:rw <zapImage> zap-baseline.py \
    -t <previewUrl> -J report.json -r report.html -m 5
  ```
  Wall-clock budget controlled by `scanTimeoutSeconds` (default 600s).
- **Parses** `report.json` into `NormalizedFinding[]`:
  - Severity from ZAP `riskdesc`: `Critical → critical`, `High → high`, `Medium → medium`, `Low → low`, `Informational → info`.
  - Category: `sast` (closest fit; ZAP findings are HTTP/auth misconfigs).
  - `ruleId = zap.<pluginid>` (or kebab-cased name if no pluginid).
  - `cwe = ["CWE-<cweid>"]` when present.
  - `file = <first instance uri>`, `remediation = <alert.solution>`.
- **Emits** `report.json` + `report.html` as evidence artifacts.

## Configuration

Per-vibe config (stored in `RepositorySecurityConfig.pluginAssignments["deploy.preview"].config`):

```yaml
provider: zap-baseline
config:
  previewUrl: https://pr-123.preview.example.com # required
  zapImage: ghcr.io/zaproxy/zaproxy:stable # optional override
  scanTimeoutSeconds: 600 # wall budget; default 600
  extraArgs: [] # additional flags appended to zap-baseline.py
```

<!-- VIBECONTROLS_OSS_FOOTER_START -->

---

## About VibeControls

**VibeControls** is the agentic engineering mission control for AI-native teams. Vibe-plugins extend the VibeControls agent with new providers, tools, sessions, tunnels, storage backends, and security stages.

- Website: <https://vibecontrols.com>
- Documentation: <https://docs.vibecontrols.com>
- Plugin SDK: <https://github.com/algoshred/vibecontrols-plugin-sdk>
- All plugins: <https://github.com/algoshred?q=vibe-plugin-&type=all>

## Credits

This plugin builds on the following upstream open-source projects. All trademarks and copyrights remain with their respective owners.

- **OWASP ZAP** — <https://github.com/zaproxy/zaproxy>

## License

Released under the [MIT License](./LICENSE).

Copyright (c) 2026 Burdenoff Consultancy Services Private Limited, Algoshred Technologies Private Limited, and all its sister companies.

Maintainer: **Vignesh T.V** — <https://github.com/tvvignesh>

**Note**: this plugin is open source under MIT. The `@vibecontrols/agent` runtime that loads and orchestrates plugins is **closed source** and proprietary to Burdenoff Consultancy Services Pvt. Ltd. If you want a fully self-hostable agent, please open an issue or contact the maintainer.

<!-- VIBECONTROLS_OSS_FOOTER_END -->
