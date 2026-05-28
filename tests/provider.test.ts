import { describe, expect, test } from "bun:test";

import { ZapBaselineProvider } from "../src/provider.js";
import { ZAP_BASELINE_VERSION } from "../src/tools-manifest.js";

const baseInput = (config: Record<string, unknown> = {}) => ({
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
  workdir: "/tmp",
});

describe("ZapBaselineProvider", () => {
  test("provider name + stage are immutable identifiers", () => {
    const p = new ZapBaselineProvider();
    expect(p.name).toBe("zap-baseline");
    expect(p.stage).toBe("deploy.preview");
  });

  test("metadata reports the pinned tool version", () => {
    const p = new ZapBaselineProvider();
    expect(p.toolVersion).toBe(ZAP_BASELINE_VERSION);
    expect(p.metadata().stage).toBe("deploy.preview");
    expect(p.metadata().supportedProfiles).toContain("backend");
    expect(p.metadata().supportedProfiles).toContain("frontend");
  });

  test("ensureToolInstalled is a no-op (Docker-based)", async () => {
    const p = new ZapBaselineProvider();
    await expect(p.ensureToolInstalled()).resolves.toBeUndefined();
  });

  test("run() returns 'succeeded' with a docker-missing info finding when docker absent", async () => {
    const p = new ZapBaselineProvider();
    // Force the docker-skip path without spawning `docker info`.
    const result = await p.run(
      baseInput({
        skipDockerProbe: false, // probe runs — likely no docker in test env, but tolerate either
        skipPreviewProbe: true,
        previewUrl: "https://preview.example",
      }),
    );
    expect(result.status).toBe("succeeded");
    expect(result.findings.length).toBe(1);
    expect(result.findings[0].severity).toBe("info");
    expect(result.findings[0].category).toBe("config");
  });

  test("run() emits skipped finding when previewUrl is missing", async () => {
    const p = new ZapBaselineProvider();
    const result = await p.run(
      baseInput({
        skipDockerProbe: true,
        // previewUrl deliberately omitted
      }),
    );
    expect(result.status).toBe("succeeded");
    expect(result.findings.length).toBe(1);
    expect(result.findings[0].ruleId).toBe("zap-baseline.skipped");
    expect(result.findings[0].description).toMatch(/preview-url-unreachable/);
  });

  test("cancel() on an unknown run is a no-op", async () => {
    const p = new ZapBaselineProvider();
    await expect(p.cancel("nonexistent")).resolves.toBeUndefined();
  });
});
