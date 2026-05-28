import { describe, expect, test, beforeAll, afterAll } from "bun:test";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import * as path from "node:path";

import { ZapBaselineProvider } from "../src/provider.js";
import { ZAP_BASELINE_VERSION, ZAP_IMAGE_DEFAULT } from "../src/tools-manifest.js";

interface TestEnv {
  workdir: string;
  fixtureReportPath: string;
}

let env: TestEnv;

const FIXTURE_REPORT = {
  "@version": "2.16.0",
  "@generated": "Wed, 28 May 2026 06:00:00",
  site: [
    {
      "@name": "https://preview.example.com",
      "@host": "preview.example.com",
      alerts: [
        {
          pluginid: "10038",
          name: "Content Security Policy (CSP) Header Not Set",
          riskcode: "2",
          confidence: "3",
          riskdesc: "Medium (High)",
          desc: "Content Security Policy is an effective measure to protect your site from XSS attacks.",
          alert: "Content Security Policy (CSP) Header Not Set",
          solution:
            "Ensure that your web server, application server, etc. set the Content-Security-Policy header.",
          reference: "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
          cweid: "693",
          wascid: "15",
          instances: [{ uri: "https://preview.example.com/", method: "GET" }],
        },
        {
          pluginid: "90034",
          name: "Cloud Metadata Potentially Exposed",
          riskdesc: "High (Low)",
          alert: "Cloud Metadata Potentially Exposed",
          desc: "The Cloud Metadata Attack attempts to abuse the metadata endpoint.",
          solution: "Disable the metadata service or restrict access.",
          cweid: "20",
          instances: [{ uri: "https://preview.example.com/api/" }],
        },
        {
          pluginid: "10010",
          name: "Cookie No HttpOnly Flag",
          riskdesc: "Low (Medium)",
          alert: "Cookie No HttpOnly Flag",
          desc: "A cookie has been set without the HttpOnly flag.",
          solution: "Ensure that the HttpOnly flag is set for all cookies.",
          cweid: "1004",
          instances: [{ uri: "https://preview.example.com/login" }],
        },
        {
          pluginid: "10049",
          name: "Storable and Cacheable Content",
          riskdesc: "Informational (Medium)",
          alert: "Storable and Cacheable Content",
          desc: "The response contents are storable by caching components.",
          solution: "Use Cache-Control appropriately.",
          cweid: "524",
          instances: [{ uri: "https://preview.example.com/" }],
        },
      ],
    },
  ],
};

beforeAll(async () => {
  const root = await fs.mkdtemp(path.join(tmpdir(), "vibe-dast-test-"));
  const workdir = path.join(root, "workdir");
  await fs.mkdir(workdir, { recursive: true });
  const fixtureReportPath = path.join(root, "fixture-report.json");
  await fs.writeFile(fixtureReportPath, JSON.stringify(FIXTURE_REPORT), "utf-8");
  env = { workdir, fixtureReportPath };
});

afterAll(async () => {
  try {
    await fs.rm(path.dirname(env.workdir), { recursive: true, force: true });
  } catch {
    /* best-effort */
  }
});

const baseInput = (workdir: string, config: Record<string, unknown> = {}) => ({
  runId: "dast-1",
  vibeId: "v1",
  workspaceId: "w1",
  repoUrl: "x",
  repoLocalPath: "/tmp",
  commit: "c",
  stage: "deploy.preview" as const,
  profile: { kind: "backend", languages: ["ts"], runtimes: ["bun"] },
  policyLevel: "advisory" as const,
  config,
  workdir,
});

describe("ZapBaselineProvider metadata", () => {
  test("provider name + stage are immutable identifiers", () => {
    const p = new ZapBaselineProvider();
    expect(p.name).toBe("zap-baseline");
    expect(p.stage).toBe("deploy.preview");
  });

  test("metadata reports the pinned tool version", () => {
    const p = new ZapBaselineProvider();
    expect(p.toolVersion).toBe(ZAP_BASELINE_VERSION);
    expect(p.toolVersion).toContain(ZAP_IMAGE_DEFAULT);
    expect(p.metadata().stage).toBe("deploy.preview");
    expect(p.metadata().supportedProfiles).toContain("backend");
    expect(p.metadata().supportedProfiles).toContain("frontend");
  });

  test("cancel() on an unknown run is a no-op", async () => {
    const p = new ZapBaselineProvider();
    await expect(p.cancel("nonexistent")).resolves.toBeUndefined();
  });
});

describe("ZapBaselineProvider run() — skip paths", () => {
  test("skips with docker-missing when docker unavailable", async () => {
    const p = new ZapBaselineProvider();
    const result = await p.run(
      baseInput(env.workdir, {
        dockerAvailableOverride: false,
        previewUrl: "https://preview.example.com",
      }),
    );
    expect(result.status).toBe("succeeded");
    expect(result.findings.length).toBe(1);
    expect(result.findings[0].ruleId).toBe("tool.docker.unavailable");
    expect(result.findings[0].description).toMatch(/docker-missing/);
    expect(result.findings[0].severity).toBe("info");
    expect(result.findings[0].category).toBe("config");
    expect(result.evidence).toEqual([]);
  });

  test("skips with target-url-missing when previewUrl absent", async () => {
    const p = new ZapBaselineProvider();
    const result = await p.run(
      baseInput(env.workdir, {
        dockerAvailableOverride: true,
        // previewUrl deliberately omitted
      }),
    );
    expect(result.status).toBe("succeeded");
    expect(result.findings[0].ruleId).toBe("target.url.unreachable");
    expect(result.findings[0].description).toMatch(/target-url-missing/);
  });

  test("skips with target-url-unreachable when URL is bad", async () => {
    const p = new ZapBaselineProvider();
    const result = await p.run(
      baseInput(env.workdir, {
        dockerAvailableOverride: true,
        previewUrl: "http://localhost:1", // refused
      }),
    );
    expect(result.status).toBe("succeeded");
    expect(result.findings[0].ruleId).toBe("target.url.unreachable");
    expect(result.findings[0].description).toMatch(/target-url-unreachable/);
  });
});

describe("ZapBaselineProvider run() — happy path with fixture", () => {
  test("parses ZAP report.json into normalized findings", async () => {
    const p = new ZapBaselineProvider();
    const result = await p.run(
      baseInput(env.workdir, {
        dockerAvailableOverride: true,
        previewUrl: "https://preview.example.com",
        reportFixturePath: env.fixtureReportPath,
      }),
    );
    expect(result.status).toBe("succeeded");
    expect(result.findings.length).toBe(4);

    // Severity distribution from fixture: high=1, medium=1, low=1, info=1.
    expect(result.summary.critical).toBe(0);
    expect(result.summary.high).toBe(1);
    expect(result.summary.medium).toBe(1);
    expect(result.summary.low).toBe(1);
    expect(result.summary.info).toBe(1);

    // Medium CSP finding
    const csp = result.findings.find((f) => f.title.includes("Content Security Policy"));
    expect(csp).toBeDefined();
    expect(csp?.severity).toBe("medium");
    expect(csp?.category).toBe("sast");
    expect(csp?.ruleId).toBe("zap.10038");
    expect(csp?.cwe).toEqual(["CWE-693"]);
    expect(csp?.file).toBe("https://preview.example.com/");
    expect(csp?.remediation).toMatch(/Content-Security-Policy/);

    // High Cloud Metadata
    const cm = result.findings.find((f) => f.title.includes("Cloud Metadata"));
    expect(cm?.severity).toBe("high");

    // Low Cookie HttpOnly
    const cookie = result.findings.find((f) => f.title.includes("HttpOnly"));
    expect(cookie?.severity).toBe("low");

    // Info storable
    const info = result.findings.find((f) => f.title.includes("Storable"));
    expect(info?.severity).toBe("info");
  });

  test("emits report.json as evidence", async () => {
    const p = new ZapBaselineProvider();
    const result = await p.run(
      baseInput(env.workdir, {
        dockerAvailableOverride: true,
        previewUrl: "https://preview.example.com",
        reportFixturePath: env.fixtureReportPath,
      }),
    );
    const reportE = result.evidence.find((e) => e.localPath.endsWith("report.json"));
    expect(reportE).toBeDefined();
    expect(reportE!.type).toBe("sarif");
    expect(reportE!.sha256).toHaveLength(64);
    expect(reportE!.sizeBytes).toBeGreaterThan(0);
  });

  test("zapRiskToSeverity handles all known riskdesc values via fixture", async () => {
    // This is exercised through parseZapReport in the happy-path test above —
    // we just double-check the boundary: an alert with riskdesc 'Critical (High)'
    // returns severity 'critical'.
    const tmp = await fs.mkdtemp(path.join(tmpdir(), "vibe-dast-crit-"));
    const reportPath = path.join(tmp, "report.json");
    await fs.writeFile(
      reportPath,
      JSON.stringify({
        site: [
          {
            alerts: [
              {
                pluginid: "99999",
                name: "Critical Test Finding",
                riskdesc: "Critical (High)",
                solution: "Fix it",
                instances: [{ uri: "https://x/" }],
              },
            ],
          },
        ],
      }),
      "utf-8",
    );
    const p = new ZapBaselineProvider();
    const wd = path.join(tmp, "wd");
    await fs.mkdir(wd, { recursive: true });
    const result = await p.run(
      baseInput(wd, {
        dockerAvailableOverride: true,
        previewUrl: "https://preview.example.com",
        reportFixturePath: reportPath,
      }),
    );
    expect(result.findings.length).toBe(1);
    expect(result.findings[0].severity).toBe("critical");
    expect(result.summary.critical).toBe(1);
    await fs.rm(tmp, { recursive: true, force: true });
  });
});
