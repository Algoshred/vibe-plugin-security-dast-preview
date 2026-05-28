/**
 * ZapBaselineProvider — implements SecurityProvider for stage `deploy.preview`.
 *
 * Real implementation:
 *  - `ensureToolInstalled()`: probes `docker info` and `docker pull` of the
 *    pinned ZAP image. Failures are non-fatal — the dockerAvailable flag is
 *    cached so run() can gracefully degrade to a skip-with-reason finding.
 *  - `run()`: HEAD-probes input.config.previewUrl, then `docker run --rm
 *    -v <workdir>:/zap/wrk/:rw <zapImage> zap-baseline.py -t <previewUrl>
 *    -J report.json -r report.html -m 5`. The JSON report is parsed into
 *    NormalizedFinding[] with severities derived from ZAP's riskdesc field
 *    (Critical→critical, High→high, Medium→medium, Low→low, Informational→
 *    info). CWE references and remediation strings are preserved per alert.
 *  - Evidence: both report.json and report.html (typed `sarif` until the
 *    meta plugin's SecurityEvidenceType union is extended with `zap-json`).
 *
 * Skip paths (status `succeeded` with one info finding):
 *  - `docker-missing` — `docker info` fails or docker binary not on PATH.
 *  - `target-url-unreachable` — previewUrl absent or HEAD probe fails.
 */
import { spawn, type ChildProcess } from "node:child_process";
import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import * as path from "node:path";

import type { HostServices } from "@vibecontrols/plugin-sdk/contract";
import { fingerprint } from "@vibecontrols/vibe-plugin-security/fingerprint";
import type {
  NormalizedFinding,
  ScanEvidenceArtifact,
  SecurityFindingCategory,
  SecurityProvider,
  SecurityProviderMetadata,
  SecurityScanInput,
  SecurityScanResult,
  SecurityScanSummary,
  SecurityStage,
  SecuritySeverity,
} from "@vibecontrols/vibe-plugin-security/types";

import { ZAP_BASELINE_VERSION, ZAP_IMAGE_DEFAULT } from "./tools-manifest.js";

interface DastPreviewConfig {
  previewUrl?: string;
  zapImage?: string;
  scanTimeoutSeconds?: number;
  extraArgs?: string[];
  /** Force a specific dockerAvailable value (testing). */
  dockerAvailableOverride?: boolean;
  /** Override the docker command (testing). */
  dockerCommandOverride?: string;
  /** Skip docker invocation and use this pre-existing report.json (testing). */
  reportFixturePath?: string;
}

export class ZapBaselineProvider implements SecurityProvider {
  readonly name = "zap-baseline";
  readonly stage: SecurityStage = "deploy.preview";
  readonly toolVersion = ZAP_BASELINE_VERSION;

  private host?: HostServices;
  private active = new Map<string, ChildProcess>();
  private dockerAvailable?: boolean;

  async init(host: HostServices): Promise<void> {
    this.host = host;
  }

  async ensureToolInstalled(): Promise<void> {
    // ZAP runs via Docker. We probe `docker info` and best-effort `docker pull`
    // the image so the first real scan starts fast. Any failure here is logged
    // and remembered on `this.dockerAvailable = false` so run() can skip.
    const dockerOk = await this.dockerInfoOk();
    this.dockerAvailable = dockerOk;
    if (!dockerOk) {
      this.host?.logger?.info?.(
        "zap-baseline-provider",
        "docker info failed — DAST scans will be skipped at run time",
      );
      return;
    }
    try {
      this.host?.logger?.info?.(
        "zap-baseline-provider",
        `pre-pulling ${ZAP_IMAGE_DEFAULT} (this may take a minute)`,
      );
      await this.runCommand("docker", ["pull", ZAP_IMAGE_DEFAULT], 60_000);
    } catch (err) {
      this.host?.logger?.warn?.(
        "zap-baseline-provider",
        `docker pull failed — will retry at scan time: ${String(err)}`,
      );
    }
  }

  async run(input: SecurityScanInput): Promise<SecurityScanResult> {
    const startedAt = Date.now();
    const cfg = (input.config as DastPreviewConfig) ?? {};

    // ── 1. Docker availability ──────────────────────────────────────────
    input.onProgress?.({ pct: 5, message: "Probing docker daemon" });

    const dockerAvailable =
      cfg.dockerAvailableOverride ?? this.dockerAvailable ?? (await this.dockerInfoOk());
    if (!dockerAvailable && !cfg.reportFixturePath) {
      return this.skipResult(
        input,
        startedAt,
        "docker-missing",
        "tool.docker.unavailable",
        "deploy.preview: ZAP baseline skipped — docker info failed.",
        "Install Docker on this host or run the scan from a CI environment that provides a Docker daemon.",
      );
    }

    // ── 2. Preview URL reachability ─────────────────────────────────────
    input.onProgress?.({ pct: 15, message: "Probing preview URL" });
    if (!cfg.previewUrl) {
      return this.skipResult(
        input,
        startedAt,
        "target-url-missing",
        "target.url.unreachable",
        "deploy.preview: ZAP baseline skipped — no previewUrl in plugin config.",
        "Set input.config.previewUrl to the URL of the preview deploy you want ZAP to scan.",
      );
    }
    if (!cfg.reportFixturePath && !(await this.previewUrlReachable(cfg.previewUrl))) {
      return this.skipResult(
        input,
        startedAt,
        "target-url-unreachable",
        "target.url.unreachable",
        `deploy.preview: ZAP baseline skipped — HEAD probe of ${cfg.previewUrl} failed.`,
        "Make sure the preview deploy is up and reachable from the agent host before triggering the scan.",
      );
    }

    // ── 3. Run zap-baseline.py ──────────────────────────────────────────
    const reportPath = path.join(input.workdir, "report.json");
    const reportHtmlPath = path.join(input.workdir, "report.html");
    const image = cfg.zapImage ?? ZAP_IMAGE_DEFAULT;
    const timeoutMs = (cfg.scanTimeoutSeconds ?? 600) * 1000;

    if (cfg.reportFixturePath) {
      // Test path: copy the fixture into place and skip the docker spawn.
      await fs.copyFile(cfg.reportFixturePath, reportPath);
    } else {
      input.onProgress?.({ pct: 25, message: "Running ZAP baseline scan" });
      const args = [
        "run",
        "--rm",
        "-v",
        `${input.workdir}:/zap/wrk/:rw`,
        image,
        "zap-baseline.py",
        "-t",
        cfg.previewUrl,
        "-J",
        "report.json",
        "-r",
        "report.html",
        "-m",
        "5",
      ];
      if (cfg.extraArgs) args.push(...cfg.extraArgs);

      const docker = cfg.dockerCommandOverride ?? "docker";
      const result = await this.spawnAndWait(docker, input.runId, args, timeoutMs);
      // zap-baseline exit codes: 0 clean, 1 warnings, 2 failures — all "scan ran".
      if (result.code !== 0 && result.code !== 1 && result.code !== 2) {
        return errored(
          input.runId,
          startedAt,
          `zap-baseline docker exit ${result.code}: ${result.stderr.slice(0, 500)}`,
        );
      }
    }

    input.onProgress?.({ pct: 85, message: "Parsing ZAP report" });

    // ── 4. Parse + normalize ────────────────────────────────────────────
    let findings: NormalizedFinding[] = [];
    try {
      const reportRaw = await fs.readFile(reportPath, "utf-8");
      findings = parseZapReport(reportRaw, this.name, cfg.previewUrl);
    } catch (err) {
      // No report — treat as scan-ran-but-empty.
      this.host?.logger?.warn?.(
        "zap-baseline-provider",
        `no ZAP report.json produced at ${reportPath}: ${String(err)}`,
      );
    }

    // ── 5. Evidence ─────────────────────────────────────────────────────
    const evidence: ScanEvidenceArtifact[] = [];
    for (const p of [reportPath, reportHtmlPath]) {
      try {
        const buf = await fs.readFile(p);
        evidence.push({
          // TODO: add `zap-json` / `zap-html` to SecurityEvidenceType in the
          // meta plugin's types. Until then we tag both as sarif so they
          // still get uploaded as evidence.
          type: "sarif",
          localPath: p,
          sha256: createHash("sha256").update(buf).digest("hex"),
          sizeBytes: buf.byteLength,
        });
      } catch {
        // optional — html may not exist when -r is dropped
      }
    }

    input.onProgress?.({ pct: 100, message: "Scan complete" });

    return {
      runId: input.runId,
      status: "succeeded",
      findings,
      evidence,
      durationMs: Date.now() - startedAt,
      summary: summarize(findings),
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
        "OWASP ZAP baseline DAST scan (zap-baseline.py via Docker) for the deploy.preview lifecycle stage.",
    };
  }

  private async dockerInfoOk(): Promise<boolean> {
    return new Promise((resolve) => {
      const child = spawn("docker", ["info"], { stdio: ["ignore", "ignore", "ignore"] });
      const t = setTimeout(() => {
        try {
          child.kill("SIGKILL");
        } catch {
          /* already gone */
        }
        resolve(false);
      }, 5000);
      child.on("close", (code) => {
        clearTimeout(t);
        resolve(code === 0);
      });
      child.on("error", () => {
        clearTimeout(t);
        resolve(false);
      });
    });
  }

  private async previewUrlReachable(url: string): Promise<boolean> {
    try {
      const ctrl = new AbortController();
      const t = setTimeout(() => ctrl.abort(), 10_000);
      const res = await fetch(url, { method: "HEAD", signal: ctrl.signal });
      clearTimeout(t);
      return res.status < 500;
    } catch {
      return false;
    }
  }

  private async runCommand(cmd: string, args: string[], timeoutMs: number): Promise<void> {
    return new Promise((resolve, reject) => {
      const child = spawn(cmd, args, { stdio: ["ignore", "ignore", "pipe"] });
      let stderr = "";
      const timer = setTimeout(() => {
        try {
          child.kill("SIGKILL");
        } catch {
          /* already gone */
        }
        reject(new Error(`${cmd} timed out after ${timeoutMs}ms`));
      }, timeoutMs);
      child.stderr?.on("data", (b: Buffer) => (stderr += b.toString()));
      child.on("close", (code) => {
        clearTimeout(timer);
        if (code === 0) resolve();
        else reject(new Error(`${cmd} exit ${code}: ${stderr.slice(0, 200)}`));
      });
      child.on("error", (err) => {
        clearTimeout(timer);
        reject(err);
      });
    });
  }

  private spawnAndWait(
    bin: string,
    runId: string,
    args: string[],
    timeoutMs: number,
  ): Promise<{ code: number | null; stdout: string; stderr: string }> {
    return new Promise((resolve) => {
      const child = spawn(bin, args, { stdio: ["ignore", "pipe", "pipe"] });
      this.active.set(runId, child);
      let stdout = "";
      let stderr = "";
      const timer = setTimeout(() => {
        try {
          child.kill("SIGKILL");
        } catch {
          /* already gone */
        }
      }, timeoutMs);
      child.stdout?.on("data", (b: Buffer) => (stdout += b.toString()));
      child.stderr?.on("data", (b: Buffer) => (stderr += b.toString()));
      child.on("close", (code) => {
        clearTimeout(timer);
        this.active.delete(runId);
        resolve({ code, stdout, stderr });
      });
      child.on("error", (err) => {
        clearTimeout(timer);
        this.active.delete(runId);
        resolve({ code: -1, stdout, stderr: err.message });
      });
    });
  }

  private skipResult(
    input: SecurityScanInput,
    startedAt: number,
    reason: string,
    ruleId: string,
    title: string,
    remediation: string,
  ): SecurityScanResult {
    const findings: NormalizedFinding[] = [
      {
        fingerprint: createHash("sha256")
          .update(`${this.name}:${reason}:${input.runId}`)
          .digest("hex"),
        ruleId,
        title,
        severity: "info",
        category: "config",
        description: `deploy.preview ZAP baseline skipped — reason: ${reason}.`,
        remediation,
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

// ── ZAP report parsing ─────────────────────────────────────────────────

interface ZapReport {
  site?: Array<{
    "@host"?: string;
    "@name"?: string;
    alerts?: ZapAlert[];
  }>;
}

interface ZapAlert {
  name?: string;
  alert?: string;
  riskdesc?: string;
  desc?: string;
  solution?: string;
  reference?: string;
  cweid?: string;
  wascid?: string;
  pluginid?: string;
  instances?: Array<{
    uri?: string;
    method?: string;
    param?: string;
    attack?: string;
    evidence?: string;
  }>;
}

function parseZapReport(
  raw: string,
  providerName: string,
  previewUrl: string | undefined,
): NormalizedFinding[] {
  let report: ZapReport;
  try {
    report = JSON.parse(raw) as ZapReport;
  } catch {
    return [];
  }
  const out: NormalizedFinding[] = [];
  for (const site of report.site ?? []) {
    for (const alert of site.alerts ?? []) {
      out.push(zapAlertToFinding(alert, providerName, previewUrl));
    }
  }
  return out;
}

function zapAlertToFinding(
  alert: ZapAlert,
  providerName: string,
  previewUrl: string | undefined,
): NormalizedFinding {
  const severity = zapRiskToSeverity(alert.riskdesc);
  const category: SecurityFindingCategory = "sast"; // closest fit; ZAP findings are HTTP/auth misconfigs
  const name = alert.name ?? "ZAP Alert";
  const ruleId = `zap.${alert.pluginid ?? nameToKebab(name)}`;
  const cwe = alert.cweid && alert.cweid !== "-1" ? [`CWE-${alert.cweid}`] : undefined;
  const firstInstance = alert.instances?.[0];
  const file = firstInstance?.uri;
  return {
    fingerprint: fingerprint({
      providerName,
      ruleId: `zap:${previewUrl ?? ""}:${name}`,
      file,
    }),
    ruleId,
    title: name,
    description: alert.alert ?? alert.desc,
    severity,
    category,
    cwe,
    file,
    remediation: alert.solution,
  };
}

function zapRiskToSeverity(riskdesc: string | undefined): SecuritySeverity {
  if (!riskdesc) return "info";
  const head = riskdesc.split(" ")[0]?.toLowerCase() ?? "";
  if (head.startsWith("critical")) return "critical";
  if (head.startsWith("high")) return "high";
  if (head.startsWith("medium")) return "medium";
  if (head.startsWith("low")) return "low";
  return "info";
}

function nameToKebab(name: string): string {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 64);
}

function summarize(findings: NormalizedFinding[]): SecurityScanSummary {
  const s: SecurityScanSummary = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) s[f.severity]++;
  return s;
}

function errored(runId: string, startedAt: number, reason: string): SecurityScanResult {
  return {
    runId,
    status: "errored",
    findings: [],
    evidence: [],
    durationMs: Date.now() - startedAt,
    summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    errorReason: reason,
  };
}
