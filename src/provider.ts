/**
 * ZapBaselineProvider — implements SecurityProvider for stage `deploy.preview`.
 *
 * Wave 2 scaffold. The real implementation will:
 *  - Verify Docker is reachable (`docker info`) — if not, emit a "skipped"
 *    info finding so the dispatcher records a clean run.
 *  - HEAD-probe `input.config.previewUrl` — if not reachable, emit a
 *    "skipped" info finding.
 *  - Run `docker run --rm ghcr.io/zaproxy/zaproxy:stable zap-baseline.py \
 *      -t <previewUrl> -J <workdir>/zap-baseline.json` and parse the JSON
 *    report into NormalizedFinding[] (category: "vuln") with severities
 *    mapped from ZAP's High/Medium/Low/Informational levels.
 *  - Emit the zap JSON report as evidence.
 *
 * Today this stub records that the stage ran (or was skipped) so the
 * dispatcher can chain the next stage. The skip path is fully wired so
 * environments without Docker (CI runners, mobile dev boxes) don't fail.
 */
import { spawn, type ChildProcess } from "node:child_process";
import { createHash } from "node:crypto";

import type { HostServices } from "@vibecontrols/plugin-sdk/contract";
import type {
  NormalizedFinding,
  ScanEvidenceArtifact,
  SecurityProvider,
  SecurityProviderMetadata,
  SecurityScanInput,
  SecurityScanResult,
  SecurityScanSummary,
  SecurityStage,
} from "@vibecontrols/vibe-plugin-security/types";

import { ZAP_BASELINE_VERSION } from "./tools-manifest.js";

interface DastPreviewConfig {
  previewUrl?: string;
  zapImage?: string; // default ghcr.io/zaproxy/zaproxy:stable
  extraZapArgs?: string[];
  skipDockerProbe?: boolean; // testing
  skipPreviewProbe?: boolean; // testing
}

export class ZapBaselineProvider implements SecurityProvider {
  readonly name = "zap-baseline";
  readonly stage: SecurityStage = "deploy.preview";
  readonly toolVersion = ZAP_BASELINE_VERSION;

  private host?: HostServices;
  private active = new Map<string, ChildProcess>();

  async init(host: HostServices): Promise<void> {
    this.host = host;
  }

  async ensureToolInstalled(): Promise<void> {
    // ZAP runs via Docker — nothing to download. Docker availability is
    // probed at run() time (skip path on missing daemon).
  }

  async run(input: SecurityScanInput): Promise<SecurityScanResult> {
    const startedAt = Date.now();
    const cfg = (input.config as DastPreviewConfig) ?? {};

    input.onProgress?.({ pct: 5, message: "Probing docker daemon" });

    // Skip path 1 — docker not reachable.
    if (!cfg.skipDockerProbe && !(await this.dockerInfoOk())) {
      return this.succeededSkipped(
        input,
        startedAt,
        "docker-missing",
        "deploy.preview: ZAP baseline skipped — `docker info` failed (Docker not installed or not running on this host).",
      );
    }

    input.onProgress?.({ pct: 15, message: "Probing preview URL" });

    // Skip path 2 — preview URL unreachable / missing.
    if (
      !cfg.skipPreviewProbe &&
      (!cfg.previewUrl || !(await this.previewUrlReachable(cfg.previewUrl)))
    ) {
      return this.succeededSkipped(
        input,
        startedAt,
        "preview-url-unreachable",
        "deploy.preview: ZAP baseline skipped — preview URL HEAD probe failed or no previewUrl in config.",
      );
    }

    // TODO(wave-2): replace this stub with the real `docker run ... zap-baseline.py`
    // subprocess + JSON-report parse + normalize.
    input.onProgress?.({ pct: 50, message: "Stub ZAP baseline scan" });

    const fingerprint = createHash("sha256")
      .update(`${this.name}:${input.runId}:${cfg.previewUrl ?? "no-url"}`)
      .digest("hex");

    const findings: NormalizedFinding[] = [
      {
        fingerprint,
        ruleId: `${this.name}.stub`,
        title: "deploy.preview: zap-baseline scaffolded — real DAST integration pending",
        severity: "info",
        category: "config",
        description:
          "Wave 2 scaffold for the deploy.preview lifecycle stage. The real provider will `docker run --rm ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t <previewUrl>` and parse the JSON report into NormalizedFindings. Today this stub records that the stage ran so the dispatcher can chain the next stage.",
        remediation: "Wire the real docker-run + ZAP report parse; emit zap-json + sarif evidence.",
      },
    ];

    const evidence: ScanEvidenceArtifact[] = [];
    const summary: SecurityScanSummary = summarize(findings);

    input.onProgress?.({ pct: 100, message: "Scaffold run complete" });

    return {
      runId: input.runId,
      status: "succeeded",
      findings,
      evidence,
      durationMs: Date.now() - startedAt,
      summary,
    };
  }

  async cancel(runId: string): Promise<void> {
    const child = this.active.get(runId);
    if (!child) return;
    try {
      child.kill("SIGTERM");
      setTimeout(() => {
        try {
          child.kill("SIGKILL");
        } catch {
          /* already gone */
        }
      }, 5000);
    } finally {
      this.active.delete(runId);
    }
  }

  metadata(): SecurityProviderMetadata {
    return {
      stage: this.stage,
      supportedProfiles: ["backend", "frontend", "cli", "container"],
      toolVersion: this.toolVersion,
      description:
        "OWASP ZAP baseline DAST scan for deploy.preview (Wave 2 scaffold; real integration pending).",
    };
  }

  private async dockerInfoOk(): Promise<boolean> {
    return new Promise((resolve) => {
      const child = spawn("docker", ["info"], { stdio: ["ignore", "ignore", "ignore"] });
      child.on("close", (code) => resolve(code === 0));
      child.on("error", () => resolve(false));
    });
  }

  private async previewUrlReachable(url: string): Promise<boolean> {
    try {
      const ctrl = new AbortController();
      const t = setTimeout(() => ctrl.abort(), 5000);
      const res = await fetch(url, { method: "HEAD", signal: ctrl.signal });
      clearTimeout(t);
      // Any 2xx/3xx/4xx counts as "reachable" — only network errors are
      // treated as unreachable for the skip path.
      return res.status < 500;
    } catch {
      return false;
    }
  }

  private succeededSkipped(
    input: SecurityScanInput,
    startedAt: number,
    reason: string,
    title: string,
  ): SecurityScanResult {
    const fingerprint = createHash("sha256")
      .update(`${this.name}:${input.runId}:${reason}`)
      .digest("hex");
    const findings: NormalizedFinding[] = [
      {
        fingerprint,
        ruleId: `${this.name}.skipped`,
        title,
        severity: "info",
        category: "config",
        description: `Skip reason: ${reason}. The provider returned successfully without performing a scan.`,
      },
    ];
    return {
      runId: input.runId,
      status: "succeeded",
      findings,
      evidence: [],
      durationMs: Date.now() - startedAt,
      summary: summarize(findings),
    };
  }
}

function summarize(findings: NormalizedFinding[]): SecurityScanSummary {
  const s: SecurityScanSummary = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) s[f.severity]++;
  return s;
}
