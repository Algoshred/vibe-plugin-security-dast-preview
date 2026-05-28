## @vibecontrols/vibe-plugin-security-dast-preview

OWASP ZAP baseline DAST provider for the `deploy.preview` lifecycle stage in [VibeControls](https://vibecontrols.com). Provider name: `zap-baseline`. Wraps the `ghcr.io/zaproxy/zaproxy:stable` Docker image. **Wave 2 scaffold — real tool integration pending; see `src/provider.ts` TODO.**

Registers itself with [`@vibecontrols/vibe-plugin-security`](https://www.npmjs.com/package/@vibecontrols/vibe-plugin-security) under the per-stage provider type `security.release` (per `PROVIDER_TYPE_FOR_STAGE("deploy.preview")`). When the user picks "zap-baseline" as their default provider for `deploy.preview`, the security meta plugin dispatches scan runs here.

## Install

```bash
vibe plugin install @vibecontrols/vibe-plugin-security-dast-preview
vibe security providers set-default --stage deploy.preview --provider zap-baseline
```

This plugin does NOT download a binary — it shells out to Docker. Make sure Docker is installed and `docker info` succeeds on the agent host. If Docker is missing or unreachable, the provider returns a "succeeded" result with a single info finding describing the skip reason — the lifecycle never blocks on local-tooling absence.

## Behavior (planned)

- `docker info` probe — skip with reason `docker-missing` when unavailable.
- `HEAD <previewUrl>` probe — skip with reason `preview-url-unreachable` when unreachable or absent.
- `docker run --rm ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t <previewUrl> -J <workdir>/zap-baseline.json`
- Parse the JSON report into `NormalizedFinding[]` with severities mapped from ZAP's High/Medium/Low/Informational levels (category `vuln`).
- Emit the JSON report as evidence.

## Configuration

Per-vibe config (stored in `RepositorySecurityConfig.pluginAssignments["deploy.preview"].config`):

```yaml
provider: zap-baseline
config:
  previewUrl: https://pr-123.preview.example.com
  zapImage: ghcr.io/zaproxy/zaproxy:stable # optional override
  extraZapArgs: [] # additional CLI flags
```

## License

Proprietary — Burdenoff Consultancy Services Pvt. Ltd.
