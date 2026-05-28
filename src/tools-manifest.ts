/**
 * No tool binary download for this plugin — ZAP baseline runs via Docker
 * (`docker run --rm ghcr.io/zaproxy/zaproxy:stable zap-baseline.py ...`).
 * Docker availability is probed at run() time and the provider returns a
 * "skipped" info finding when Docker is unavailable.
 *
 * We still export a pinned `ZAP_BASELINE_VERSION` constant so the
 * provider's `toolVersion` and telemetry events carry the upstream image
 * tag we expect — bumping the Docker tag is an audited operation.
 */

export const ZAP_BASELINE_VERSION = "zap-baseline@2.16.0 (via ghcr.io/zaproxy/zaproxy:stable)";
