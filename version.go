package traefikoidc

// devPluginVersion is the placeholder carried by source-tree / local / test
// builds. Telemetry is suppressed while the plugin still reports this sentinel,
// so only stamped release builds emit a "plugin loaded" ping.
const devPluginVersion = "0.0.0-dev"

// traefikoidcPluginVersion is the released version of this plugin. It is stamped
// at release time by ./workflow-prepare.sh (invoked by the shared go-release
// workflow before GoReleaser builds and tags), which rewrites the string below
// to the computed semver.
//
// Traefik runs this plugin under Yaegi, where the version cannot be resolved
// from build info at runtime (debug.ReadBuildInfo sees Traefik's build graph,
// not the interpreted plugin). This build-stamped constant is therefore the
// single source of truth for the version reported by anonymous usage telemetry.
const traefikoidcPluginVersion = "1.0.26"
