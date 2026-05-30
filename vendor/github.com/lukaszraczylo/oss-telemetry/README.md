# oss-telemetry

A tiny Go client that fires one anonymous "this binary started" ping at a
central ingest endpoint. Designed to be embedded in your own open-source
projects so you can see approximate adoption and version spread without
collecting anything that could identify a user.

This is the **client library only**. The ingest endpoint, server-side
deduplication, rate limiting, and metrics are out of scope here.

## What it sends

A single HTTP `POST` per call to `Send`:

```json
{
  "project": "my-tool",
  "version": "1.2.3",
  "ts": 1747782200
}
```

No identifiers, no IP, no machine info, no user data. The server dedupes
incoming requests; the client just fires and forgets.

## Failproof by design

- Never blocks the caller — work runs in a goroutine.
- Never panics — the goroutine recovers internally.
- Never returns errors — bad input and network failures are silently dropped.
- Never retries, never persists state, never reads back.
- 2-second hard timeout on every request.
- Zero third-party dependencies (Go stdlib only).

The endpoint is hardcoded and not overridable from consuming code, by design.

## Install

```bash
go get github.com/lukaszraczylo/oss-telemetry
```

Requires Go 1.22+.

## Usage

```go
package main

import (
    "time"

    telemetry "github.com/lukaszraczylo/oss-telemetry"
)

const version = "1.2.3"

func main() {
    telemetry.Send("my-tool", version)

    // ... your program runs ...

    // Only needed for short-lived CLIs that may exit before the goroutine
    // finishes its POST. Long-running services do not need this.
    telemetry.Wait(2 * time.Second)
}
```

Call `Send` once at boot. Calling it more often just sends more pings; the
server deduplicates.

## Disabling telemetry

If you ship a binary that imports this library, link your users to this
section (`https://github.com/lukaszraczylo/oss-telemetry#disabling-telemetry`)
so they can find the opt-out paths.

Any one of these turns it off:

| Mechanism                                | How                                                              |
| ---------------------------------------- | ---------------------------------------------------------------- |
| Universal opt-out                        | `DO_NOT_TRACK=1`                                                 |
| Library-wide opt-out                     | `OSS_TELEMETRY_DISABLED=1`                                       |
| Project-specific opt-out                 | `<UPPER_PROJECT>_DISABLE_TELEMETRY=1`                            |
| Programmatic (e.g. behind a `--no-telemetry` flag) | `telemetry.Disable()` before the first `Send`          |

Project-specific env var derivation: uppercase the project name and replace
`-` with `_`. For `my-tool` the variable is `MY_TOOL_DISABLE_TELEMETRY`.

Truthy values: `1`, `true`, `yes`, `on` (case-insensitive). Anything else is
treated as "not set".

## Validation rules (silently dropped if violated)

- `project`: matches `^[a-z0-9-]+$`, length 1–64.
- `version`: matches `^[A-Za-z0-9.+_-]+$`, length 1–32.

Bad input is a no-op — the library never logs, never errors, never crashes.

## API

```go
// Fire a single ping in the background. Returns immediately.
func Send(project, version string)

// Suppress all subsequent Send calls in this process. Idempotent.
func Disable()

// Block until in-flight pings complete or timeout elapses, whichever first.
// Useful for short-lived CLI processes.
func Wait(timeout time.Duration)
```

## Testing

```bash
go test -race ./...
```

## License

Pick one before publishing. None bundled.
