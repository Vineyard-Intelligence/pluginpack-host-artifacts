# Host Artifacts

A Vineyard **plugin pack** that brings a host's own record of what ran and where it went into the
investigation. No server, no API key, no network scope — **the exports are parsed on your machine**
and nothing is looked up.

One plugin:

- **Process Activity Import** (`run.vineyard.plugins.process_activity_import`) — reads event exports
  picked in the Run dialog (no selection). Creates a **Process** node per process GUID, linked to the
  **IP addresses** it connected to, the **domains** it queried, the process that **spawned** it, and
  the **File** node (with its hashes) it **executed from**.

## What it reads

Sysmon events **1** (process create), **3** (network connection) and **22** (DNS query), and ECS
process, network and DNS events. Every record needs a per-execution process id — Sysmon's
`ProcessGuid` or ECS `process.entity_id` — because `endpoint.process` is identified by
(`process_guid`, `process_name`, `pid`), and without the GUID one image name and PID on two hosts
become one process. Records without one are skipped and counted, which is why process lists and
netstat tables are not read.

| Export | How it is usually made | Read as |
|---|---|---|
| Windows event XML | `wevtutil qe Microsoft-Windows-Sysmon/Operational /f:xml > sysmon.xml`, Event Viewer → Save as XML, `.ToXml()` | `<Event>` elements |
| PowerShell | `Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational \| Select TimeCreated, Id, MachineName, Message \| ConvertTo-Json` | the rendered `Message` |
| Event Viewer CSV | Save All Events As… → CSV | the headerless message column |
| KAPE | EvtxECmd `--csv` or `--json` over the Sysmon log | the `Payload` column |
| Velociraptor | an event-log artifact over the Sysmon channel (e.g. `Windows.EventLogs.EvtxHunter`), exported as JSON or CSV | `EventData` |
| evtx_dump | `evtx_dump -o json` or `-o jsonl` | `Event.EventData` |
| Winlogbeat / Elastic | the Sysmon index exported as JSON lines | `winlog.event_data` |
| A SIEM's CSV | one column per Sysmon field (e.g. Splunk with the Sysmon add-on) | the columns |
| ECS (Elastic Defend and other EDRs mapped to ECS) | JSON lines, Elasticsearch `hits.hits`, or Kibana's CSV | `process.*`, `source.*`, `destination.*`, `dns.*` |

JSON, JSON lines, CSV, TSV and XML are told apart by content, and UTF-8 or UTF-16 (what Windows
PowerShell 5.1 writes) by the byte-order mark or the NUL pattern. A NUL or an unpaired surrogate in a
value (both are legal JSON escapes, and Windows allows the second in file names) is written as
U+FFFD, because the server refuses a row that holds either.

ECS gives a connection's direction as `ingress`/`egress`, and Elastic Defend as `incoming`/`outgoing`;
both are read, and a record with neither is placed by `host.ip`, the host's own addresses. Defend
also logs each connection again when it closes (`disconnect_received`) and each lookup as
`lookup_requested` and then `lookup_result`; a link's `events` counts the connection or lookup
once, as the larger of its opening and closing records.

The Run dialog takes at most 25 MB
per file, 50 files and 250 MB per run, so filter the export to the hosts and time you are
investigating first.

## What it writes

| Node | Fields |
|---|---|
| `endpoint.process` | `process_name` (image file name), `process_guid` (`{lower-case}` for a GUID, otherwise as given), `pid`, `parent_pid`, `command_line`, `user`, `start_time`; not declared by the type: `hostname`, `image_path`, `integrity_level`, `destinations_not_imported` when a process reached more than 200 destinations, and `command_line_truncated` with the full `command_line_length` when the command line was cut to fit one node |
| `endpoint.file` | the executable, only when the export carries its hash: `file_name`, `file_path`, `sha256`, `md5`, `hostname`; not declared: `sha1`, `imphash`, `original_file_name`, `company`, `product`, `file_version`, `file_description` |
| `infrastructure.ip_address` | `ip_address` (dotted quad, or RFC 5952 IPv6; an IPv4-mapped address is the IPv4 address), `version` |
| `infrastructure.domain` | `domain_name` (lower case, no trailing dot) |

| From → to | Label | Edge data |
|---|---|---|
| process → process | `spawned` | none |
| process → file | `executed from` | none |
| process → IP address | `connected to`, or `accepted connection from` when every event was inbound | `source` (`sysmon` or `ecs`), `events`, `direction` (`outbound`, `inbound`, `both`), `first_seen`, `last_seen`, `ports` (the service port, up to 20; `port_count` past that), `protocols`, `remote_hostnames` (the logging host's name for the peer) |
| process → domain | `queried` | `source`, `events`, `first_seen`, `last_seen`, `answers` (addresses and CNAME targets, up to 20), `failed_events` and `statuses` when a query failed |

The backend keeps one edge per ordered pair of nodes, so every event for a pair is one edge with a
summary. A later import of the same pair replaces the summary rather than adding to it, and a key it
has no value for (`failed_events` once the name resolves) becomes null. A link already in the
project keeps its label, whoever wrote it — the plugin reads edges (`edge:read`) only for this — so
an analyst's "C2 beacon" stays, and a pair first seen inbound stays `accepted connection from` with
`direction: both` once an outbound connection appears.

On a link already in the project the plugin writes only the summary, by the edge's id
(`updateEdge`), never the label. A link with no summary (`spawned`, `executed from`) is re-asserted
only when it still carries the pack's own wording. Restating someone else's wording would be worse
than noise: the host takes the same label from a second writer as an independent source for the
link and records it in `corroborated_by`, and this pack would only have read the label back.

A new link is stored with its summary from the first import, and the link's Properties panel and
the review show it under **Recorded with this link**. A later import sends every summarised link's
summary again, changed or not, because the plugin cannot compare it (`edges()` returns no data).
The host does: it stages an edge write only when a key differs from what the link stores, a null
matching a key the link does not have. Importing the same export twice therefore stages nothing,
and a later export puts up for review only the links whose summary it changes.

**Left out:** loopback, link-local, multicast and unspecified addresses always; private-network
addresses (RFC 1918, CGNAT, unique-local) and internal names (single-label, `.local`, `.corp`,
`.home.arpa`, …) unless *Include private-network addresses and internal names* is on; reverse
lookups; processes with no network or DNS activity unless *Also import processes with no network or
DNS activity* is on. Each is counted in the run summary.

**Caps:** a run stops at 1,500 nodes, 3,000 links or 3 MB of changes, whichever comes first, so the
change set fits one batch request (4 MiB). The bytes are counted as the server counts the request:
JSON with every character outside ASCII as a six-byte `\uXXXX` escape, so a Korean command line
costs twice what it does in UTF-8. Processes go in this order: those that reached infrastructure
already in the project, then the rest by first activity. The parents of each are followed upward,
16 at most. One node's data is kept under 200 KB the same way, below the server's 256 KiB per row:
a longer command line (Linux allows megabytes of arguments; Windows stops at 32,767 characters,
which always fits) is cut to fit, keeping its start.

## Privacy

Host names, user names and command lines become node fields. In a project on a Vineyard server they
are stored on that server like any other node; for host data that must stay on the machine, use the
desktop app in local mode.

## Layout

- `plugins/host-artifacts.manifest.json` — the pack manifest (catalog entry source), generated from
  the bundle by `gen-manifest.mjs`.
- `src/` — the source of the bundle: `main.ts` (the plugin), `records.ts` (bytes → records),
  `events.ts` (records → events), `model.ts` (events → drafts, under the caps), `net.ts` (addresses
  and names), `sdk.ts` (the copied SDK).
- `dist/` — the runnable bundle.
- `test/` — synthetic fixtures (`make-fixtures.mjs` says how they were made) and the entry the tests
  bundle to reach the parsers directly.

## Building and testing

`src/` is the source of `dist/pack.mjs`. The build pins esbuild, so the published bundle can be
checked against the source:

```bash
node build.mjs && node gen-manifest.mjs
git diff --exit-code dist/pack.mjs plugins/
node test-plugin.mjs
```

`test-plugin.mjs` validates writes against the real Endpoint and Infrastructure type packs. It finds
`typepack-basic/typepacks` in a directory above this one, or in `HOST_ARTIFACTS_TYPEPACKS`.
`npm install && npm run typecheck` type-checks the source.

Licence: Apache-2.0.
