/**
 * @vibecontrols/vibe-plugin-security-dast-preview
 *
 * OWASP ZAP baseline DAST provider for the `deploy.preview` lifecycle
 * stage. Registers as a `security.release` provider (per
 * PROVIDER_TYPE_FOR_STAGE) with @vibecontrols/vibe-plugin-security on
 * the host's ServiceRegistry.
 */
import { ProviderRegistry, TelemetryEmitter, createLifecycleHooks } from "@vibecontrols/plugin-sdk";
import type {
  HostServices,
  ProfileContext,
  VibePlugin,
  VibePluginFactory,
} from "@vibecontrols/plugin-sdk/contract";

import { ZapBaselineProvider } from "./provider.js";

const PLUGIN_NAME = "security-dast-preview";
const PLUGIN_VERSION = "2026.528.1";

export const createPlugin: VibePluginFactory = (_ctx: ProfileContext): VibePlugin => {
  const provider = new ZapBaselineProvider();
  const telemetry = new TelemetryEmitter(PLUGIN_NAME, PLUGIN_VERSION);

  const lifecycle = createLifecycleHooks({
    name: PLUGIN_NAME,
    telemetryEventName: "security.dast-preview.ready",
    onInit: async (host: HostServices) => {
      await provider.init(host);
      const registry = new ProviderRegistry(host);
      registry.registerProvider("security.release", "zap-baseline", provider);
      telemetry.emit("security.dast-preview.registered", {
        provider: "zap-baseline",
        toolVersion: provider.toolVersion,
      });
    },
  });

  return {
    name: PLUGIN_NAME,
    version: PLUGIN_VERSION,
    description:
      "OWASP ZAP baseline DAST scan for the deploy.preview lifecycle stage. Wave 2 scaffold.",
    tags: ["backend", "provider", "integration"],
    capabilities: {
      storage: "rw",
      subprocess: true,
      audit: true,
      telemetry: true,
    },
    onServerStart: lifecycle.onServerStart,
    onServerStop: lifecycle.onServerStop,
  };
};

export default createPlugin;
export { ZapBaselineProvider } from "./provider.js";
