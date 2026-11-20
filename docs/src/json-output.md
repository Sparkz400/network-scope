# JSON output and schemas

Every JSON document the program prints names its format in a top-level `schema` member, `network-scope/<kind>/v1`, so a script can check what it is parsing before it reads anything else. The shape of every kind is described by a hand-written JSON Schema (draft 2020-12) in [`docs/schema/`](https://github.com/Sparkz400/network-scope/tree/main/docs/schema), one file per kind: `<kind>.v1.schema.json`.

| Kind | Printed by | Shape |
| --- | --- | --- |
| `scan` | `scan` and `export ID` with `--format json`, the GUI JSON export | The saved scan (`targets`, `complete`, `settings`, `hosts`, `observations`, `notes`, `sent`) |
| `host` | `scan` and `export ID` with `--format jsonl` | One responding host per line; **every line** carries `schema` |
| `diff` | `diff OLD NEW --format json` | `summary`, `changes`, `new_findings`, `resolved_findings`, `unconfirmed_findings`, `ignored_keys` |
| `diff-lines` | `diff OLD NEW` (default format) | `lines`: the change lines |
| `devices` | `devices ID` | `devices`: one record per device |
| `device-history` | `devices --history MAC\|IP --format json` | The timeline of one device |
| `findings` | `findings ID` | `findings` |
| `scans` | `history` | `scans`: the saved scans |
| `alerts` | `alerts` | `alerts`: the stored alerts |
| `alert` | `monitor` on stdout and in `--alerts FILE` (one line per alert), the webhook body | One alert; every line carries `schema` |
| `ot-assets` | `ot-assets ID --format json`, the GUI export | `assets` |
| `feeds-status` | `feeds status` | What the KEV/EPSS cache holds |
| `interfaces` | `interfaces` | `interfaces`: `[id, description]` pairs |
| `changes` | `changes --format json` | `since`, `summary`, the new, gone and changed devices, `new_risks`, `resolved_risks`, `unconfirmed_risks` |
| `baseline` | `baseline show --format json` | `approved_at` and the `entries` (expected devices) |
| `risk-score` | `findings ID --top N --format json` | `network`, `hosts` (scores 0 to 100) and `top_fixes` |
| `import-summary` | `import KIND FILE --format json` | `kind`, `merged`, `skipped`, `notes` |
| `dry-run` | `scan`, `monitor`, `trace` and `dcp` with `--dry-run --format json`; the MCP `scan` tool with `dry_run` | `command`, `packets_sent` (always 0), `groups` or `packets`, `scope` |
| `mcp-where-seen`, `mcp-findings-gained`, `mcp-scan` | The MCP tools `search_inventory`, `findings_gained` and `scan` ([MCP server](mcp.md)); the other MCP tools return the kinds above | Search matches, hosts that gained a finding, a scan summary |

A list is wrapped in an object (`{"schema": "network-scope/findings/v1", "findings": [...]}`) because a bare array has no room for the identifier. Output that was a bare array before this format existed (`devices`, `findings`, `history`, `alerts`, `ot-assets`, `interfaces`, the default `diff`, `devices --history`) changed shape; scripts read the list from the named member (`jq '.findings[]'`). CSV, HTML, Markdown, nmap XML and text formats are not JSON and carry no identifier.

## Compatibility promise

- **Additive changes keep `v1`.** A new member, or a new value in an open-ended member (an identity key, a finding id, a change kind), does not change the version. Consumers must ignore members they do not know; the schema files do not forbid extra members.
- **Breaking changes bump the version** (`v2`): removing or renaming a member, changing a type or the meaning of a value, or changing the envelope. The old version stays available for at least one release after the new one becomes the default: `--json-schema v1` prints it, and the schema files of both versions are kept in `docs/schema/`.
- `--json-schema VERSION` works with every command. Today `v1` is the only version, so it is both the default and the only accepted value; any other value is an error (exit status 1, nothing printed), which keeps a script that pins a version from silently getting a different one.
- The identifier of a record never changes within a version, so `schema == "network-scope/findings/v1"` is a safe check.

## Using the schemas

The files are plain JSON Schema and work with any validator. The repository's own tests validate real output against them (`tests/cli_json_schema.rs`, `core/src/schema.rs`) with a small checker that implements only the keywords the files use (`type`, `properties`, `required`, `items`, `enum`, `const`, `minimum`, `maximum`, `minItems`, `maxItems`, `minLength`, `maxLength`, `additionalProperties: false`, `$ref` to `#/$defs/...`) and rejects any other keyword, so a schema cannot promise more than the tests verify. The schemas list the members a consumer can rely on; large free-form members (`settings`, `identity`, `observations`) are described as objects only.

```sh
network-scope-cli findings 3 --min-severity high | jq -r '.findings[] | "\(.severity) \(.ip) \(.id)"'
network-scope-cli export 3 --format jsonl | jq -c 'select(.schema == "network-scope/host/v1") | .ip'
```
