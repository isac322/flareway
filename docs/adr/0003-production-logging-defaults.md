# ADR 0003: Production logging defaults

- Status: Accepted
- Date: 2026-09-23
- Issue: [#96](https://github.com/isac322/flareway/issues/96)

## Context

The controller manager logs through controller-runtime's zap integration (`sigs.k8s.io/controller-runtime/pkg/log/zap`). Its `zap.Options` struct picks the encoder, level, stacktrace level, and sampling from one switch, `Development`, and `opts.BindFlags` exposes that switch and its parts as `--zap-*` flags.

The controller, Helm chart, and Kustomize manifests must expose consistent production logging defaults and supported overrides. The decision balances machine-readable output, diagnostic detail, sampling, and credential safety, and it settles three things: the binary's own default, how the chart and manifests express logging, and which logging paths the policy covers.

Zap's `Development` mode controls all of those from one switch. Its profile is unsuitable for standard installs (issue #96): console-encoded, multi-line output that log pipelines cannot parse as JSON; a `debug` level dominated by the per-request `V(1)` line `Cloudflare API request completed` from `internal/cloudflare/client.go`; stacktraces on warnings and panics on DPanic entries; and no sampling. The shipped default must keep that profile opt-in and expose the zap flags as supported chart and manifest overrides.

## Decision

### Binary default

`cmd/main.go` builds the logger from `zap.Options{Development: false}` after `opts.BindFlags(flag.CommandLine)` and installs it with `ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))`. With no flags, controller-runtime's production defaults apply:

| Setting | Value |
|---|---|
| Encoder | JSON |
| Level | `info` |
| Stacktrace level | `error` (as a `"stacktrace"` field) |
| Time encoding | RFC 3339 |
| Destination | stderr |
| Sampling | on, see below |

A binary run without flags, a chart install, and a Kustomize build all produce the same output format.

### Flags and accepted values

The manager accepts the standard controller-runtime flags. The policy uses three of them:

| Flag | Accepted values |
|---|---|
| `--zap-devel` | `true`, `false` |
| `--zap-log-level` | `debug`, `info`, `error`, `panic`, or a positive integer `N` (logr `V(N)`) |
| `--zap-encoder` | `json`, `console` |

`warn` is not an accepted level; the flag parser rejects it. An explicit level or encoder flag always overrides the development-mode default for that setting. `--zap-devel=true` combined with explicit `--zap-log-level=info` and `--zap-encoder=json` therefore keeps JSON at `info` and turns on only the development semantics: no sampling, warn-level stacktraces, full object dumps, and panics on DPanic.

### Sampling

The controller-runtime production sampler stays in place. Per (level, message) pair it passes the first 100 entries each second and then one in every 100. Sampling covers zap levels from `-1` up, so debug/`V(1)`, info, and error entries are all sampled; only `V(N)` with `N >= 2` bypasses it. Error bursts are thinned, never fully suppressed. `--zap-devel=true` or an integer level of `2` or higher turns the sampler off; `debug` does not.

### Helm chart

The chart exposes three values, each mapped to one flag (see the [chart README](../../charts/flareway/README.md)):

```yaml
logging:
  development: false  # --zap-devel
  level: info         # --zap-log-level
  encoder: json       # --zap-encoder
```

- The `flareway.loggingArgs` helper in `templates/_helpers.tpl` renders all three flags unconditionally, as the last entries of the manager `args`, so they win over any earlier value.
- Each key falls back to its default with `dig` (which preserves an explicit `false`), so a values file without a `logging` key, `--set logging=null`, or a partial map such as `--set logging.level=debug` still renders all three flags.
- `values.schema.json` makes `logging` an object with `additionalProperties: false`. `level` must be one of the strings `debug`, `info`, `error`, `panic`, or an integer from `1` to `6`; numeric strings are rejected. `encoder` must be `json` or `console`. No key is required.
- The chart exposes no other zap option: no stacktrace level, time encoding, or free-form extra args.

The integer cap of `6` is deliberate. The raw `--zap-log-level` flag accepts larger values, but at `8` and above client-go logs API request and response bodies, including Secret contents (truncated to 1024 bytes at `8` and 10240 bytes at `9`, complete from `10`). The chart does not offer a path to that output, and the chart README and [Troubleshooting](../operations/troubleshooting.md) warn against the raw flag.

### Kustomize base

`config/manager/manager.yaml` appends the same three flags with production values: `--zap-devel=false`, `--zap-log-level=info`, `--zap-encoder=json`.

`hack/verify-runtime-defaults.sh` checks both surfaces. For the default Helm render and the Kustomize build, the manager container args must contain each of the three production flags exactly once and no other value for those flags. A Helm render with `logging.development=true`, `logging.level=debug`, and `logging.encoder=console` must render exactly those three values.

### Scope of the policy

The policy covers the controller-runtime logger only. Two other log sources keep their own formats and are documented exceptions:

- client-go's global klog output, for rare lines such as `HTTP2 has been explicitly disabled` or warnings about invalid `HTTP2_*` environment values, printed in klog's text format;
- gRPC's own logger, which may print rare ERROR-severity text lines.

The manager does not route klog or grpclog into zap. Contextual klog calls that carry the controller logger in their context already emit JSON through it.

### CI

The shipped default is `info`. The end-to-end workflow (`.github/workflows/e2e.yaml`) rewrites `--zap-log-level=info` to `debug` in its rendered manifest so the `V(1)` Cloudflare request lines stay in the collected `controller.log` artifacts, and fails if the rewrite did not apply. The conformance run keeps the shipped default. Before artifacts are uploaded, the e2e workflow redacts known credential keys and every `Bearer` token by matching both patterns against the original text and masking the union of their spans.

## Consequences

- Standard installs emit one JSON object per line on stderr at `info`, with error stacktraces in a `"stacktrace"` field. Log pipelines can parse the output without multi-line handling.
- The per-request Cloudflare `V(1)` line is off by default. Operators enable it with `logging.level=debug` or `logging.level=1`, as described in [Troubleshooting](../operations/troubleshooting.md#debug-logging).
- Under bursts, repeated identical messages are sampled, including errors. Operators who need every line set `logging.development=true` or an integer level of `2` or higher.
- Human-readable console output at `debug` needs all three values: `logging.development=true`, `logging.level=debug`, `logging.encoder=console`. Setting `development=true` alone keeps JSON at `info`.
- Rare klog and gRPC text lines can appear between JSON lines. Log filters must tolerate non-JSON lines, for example `jq -R 'fromjson?'`.
- A Helm upgrade with `--reuse-values` from a values set without `logging` renders the defaults, because every key falls back individually.

## Alternatives considered

| Alternative | Reason rejected |
|---|---|
| Keep the development default in the binary and pass `--zap-devel=false` only from the chart and Kustomize | A binary run without flags would still differ from deployed installs, and the issue asked for a consistent production default at the entrypoint. |
| Build a custom zap core to fix the sampler or encoder | Duplicates controller-runtime logic and bypasses its `--zap-*` flags for no functional gain. The upstream sampler behavior is documented. |
| Route global klog into zap with `klog.SetLoggerWithOptions(logger, klog.ContextualLogger(true))` | Makes client-go's request and response body logging reachable from calls with a bare context, so a raw level of `8` or higher could print Secret data during startup. It also emits klog warnings and fatal lines at info severity. |
| Add a grpclog adapter | New adapter code for rare ERROR lines only. The lines are documented instead. |
| Remap xDS adapter log levels (for example Info to `V(1)`) | Its `open delta watch` Info lines are useful operational signals. Remapping is a separate decision. |
| Switch all CI to debug, or keep all CI at the default | Only e2e needs the `V(1)` triage stream. Conformance keeps the shipped default so CI still exercises it. |
| Expose `logging.extraArgs`, stacktrace level, or time encoding | Widens the chart surface without a stated need. Three values cover the requested behavior. |
| Require all three `logging` keys in the schema | Breaks `helm upgrade --reuse-values` from values without `logging` and rejects `--set logging=null` or partial maps. Per-key defaults in the helper handle those cases. |
| Allow integer levels up to 128 | Levels of `8` and higher expose API bodies, including Secrets, through a documented chart value. |
