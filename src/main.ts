// Host Artifacts — Process Activity Import: host event exports the analyst picked → endpoint.process
// nodes linked to the addresses and domains they reached, the process that spawned each one, and
// the executable (endpoint.file, with its hashes) it ran from.
//
// The files arrive as File objects in `ctx.params.exports` and are parsed here, in the sandbox. The
// plugin declares no network scope: an export of an incident host is exactly the data an analyst
// may not send anywhere, and there is nothing to look up — the value is the host's own record of
// what ran and where it went, joined to the infrastructure the rest of the investigation found.
import { definePlugin, definePluginPack } from './sdk';
import type { HostContext, RunResult } from './sdk';
import { decodeText, readRecords } from './records';
import type { FileFormat } from './records';
import { normalize } from './events';
import { CAPS, addEvent, createModel, knownIp, knownName, plan } from './model';
import type { Options, Plan } from './model';
import { parseAddress, parseName } from './net';

// Two versions on purpose. The pack's is the one installed projects compare to offer an update, and
// it moves on every release; the member's moves only when this plugin's own behaviour does.
const PACK_VERSION = '1.0.0';
const PLUGIN_VERSION = '1.0.0';

/** Destinations already in the project, as the keys `plan` ranks by. */
async function knownDestinations(ctx: HostContext): Promise<Set<string>> {
    const out = new Set<string>();
    const list = ctx.graph?.list;
    if (!list) return out;
    try {
        const { nodes } = await list();
        for (const n of nodes) {
            const t = n.type ?? '';
            if (t === 'infrastructure.ip_address' || t === 'ip_address') {
                const a = parseAddress(n.data?.ip_address);
                if (a) out.add(knownIp(a.ip));
            } else if (t === 'infrastructure.domain' || t === 'domain') {
                const d = parseName(n.data?.domain_name);
                if (d) out.add(knownName(d.name));
            }
        }
    } catch {
        // Ranking is a nicety; a failed read only means no process is moved up the order.
    }
    return out;
}

const pairKey = (from: string, to: string) => `${from}\u0000${to}`;

interface LiveEdge {
    id: string;
    label: string;
}

/**
 * Every link already in the project, by its ordered pair of live node ids.
 *
 * The backend holds one edge per ordered pair, so `createEdge` on a linked pair is a proposal to
 * relabel it. Read so that this run never makes one: an analyst who renamed `connected to` to
 * "C2 beacon" would otherwise be asked, on every later import, to put this pack's wording back.
 * The same holds for this pack's own labels: a pair first seen inbound keeps `accepted connection
 * from` once an outbound connection appears, and its `direction` says `both`.
 */
async function liveEdges(ctx: HostContext): Promise<Map<string, LiveEdge>> {
    const out = new Map<string, LiveEdge>();
    const edges = ctx.graph?.edges;
    if (!edges) return out;
    try {
        for (const e of await edges()) {
            out.set(pairKey(String(e.from_node_id), String(e.to_node_id)), { id: String(e.id), label: e.label ?? '' });
        }
    } catch {
        // Unread, every link is written with this pack's own label, which is what a project without
        // the scope gets anyway.
    }
    return out;
}

const n = (k: number, one: string, many = `${one}s`) => `${k.toLocaleString('en-US')} ${k === 1 ? one : many}`;

const FORMAT_NAMES: Record<FileFormat, string> = {
    json: 'JSON',
    'json-lines': 'JSON lines',
    csv: 'CSV',
    tsv: 'TSV',
    xml: 'event XML',
    empty: 'empty',
    unknown: 'unrecognised',
};

const TYPE_MISSING = /is not defined by any installed typepack/;

/** The switch's label, which the summary quotes when it left something out because of it. */
const INCLUDE_PRIVATE_TITLE = 'Include private-network addresses and internal names';

const processActivityImport = definePlugin({
    manifest: {
        identifier: 'run.vineyard.plugins.process_activity_import',
        content_type: 'vineyard:plugin',
        name: 'Process Activity Import',
        version: PLUGIN_VERSION,
        description:
            'Reads Sysmon (events 1, 3 and 22) or ECS process, network and DNS event exports picked in the Run dialog (no selection), locally, as JSON, JSON lines, CSV or Windows event XML. Creates a Process node per process GUID, linked to the IP addresses it connected to, the domains it queried, the process that spawned it and the File node (with hashes) it executed from.',
        icon: 'cpu',
        author: { name: 'VINEYARD', url: 'https://vineyard.run' },
        license: 'Apache-2.0',
        platforms: {
            primary: 'web',
            web: { runtime: 'sandbox-js', entry: 'dist/pack.mjs' },
            desktop: { runtime: 'sandbox-js', entry: 'dist/pack.mjs' },
        },
        io: {
            consumes: [],
            produces: [
                { typepack: 'run.vineyard.typepacks.endpoint', category: 'endpoint', name: 'process' },
                { typepack: 'run.vineyard.typepacks.endpoint', category: 'endpoint', name: 'file' },
                { typepack: 'run.vineyard.typepacks.infrastructure', category: 'infrastructure', name: 'ip_address' },
                { typepack: 'run.vineyard.typepacks.infrastructure', category: 'infrastructure', name: 'domain' },
            ],
        },
        // No `accept` on the picker. It filters by MIME type, and the OS gives JSON lines, Velociraptor
        // exports and evtx_dump output no type at all, so any filter would refuse real exports. The
        // content is sniffed instead (records.ts).
        params: {
            type: 'object',
            properties: {
                exports: {
                    type: 'array',
                    format: 'file',
                    title: 'Event exports',
                    description:
                        'Sysmon events 1, 3 and 22, or ECS process, network and DNS events, as JSON, JSON lines, CSV or event XML. Filter to the hosts and time you are investigating first.',
                },
                include_private: {
                    type: 'boolean',
                    title: INCLUDE_PRIVATE_TITLE,
                },
                include_inactive: {
                    type: 'boolean',
                    title: 'Also import processes with no network or DNS activity',
                },
            },
            required: ['exports'],
        },
        // node:read only to rank by what the project already holds, edge:read only to keep the label
        // a link already has (and to address it by id: updateEdge comes with edge:create); no node is
        // updated in place.
        scopes: { graph: ['node:read', 'node:create', 'edge:read', 'edge:create'] },
        lifecycle: { persistence: 'opt-in', controls: ['progress', 'cancel'], progress: 'determinate' },
    },
    async run(ctx): Promise<RunResult> {
        const files = (Array.isArray(ctx.params?.exports) ? ctx.params.exports : []) as File[];
        if (!files.length) {
            return { summary: 'No exports provided — pick one or more files in the Run dialog', counts: { files: 0 } };
        }
        const opts: Options = { includePrivate: ctx.params?.include_private === true, includeInactive: ctx.params?.include_inactive === true };
        const model = createModel();
        const read: string[] = [];
        let unreadableFiles = 0;
        let unreadablePieces = 0;

        // ---- read: one file materialised at a time ------------------------------------------
        for (let i = 0; i < files.length; i++) {
            if (ctx.signal?.aborted) break;
            const file = files[i];
            const name = file?.name || `file-${i + 1}`;
            ctx.progress?.set?.({ percent: Math.round((i / files.length) * 60), message: `Reading ${name} (${i + 1}/${files.length})` });
            let text: string;
            try {
                text = decodeText(new Uint8Array(await file.arrayBuffer()));
            } catch {
                unreadableFiles++;
                continue;
            }
            const { format, records, unreadable } = readRecords(text);
            unreadablePieces += unreadable;
            const before = { sysmon: 0, ecs: 0 };
            for (const rec of records) {
                model.tally.records++;
                const ev = normalize(rec);
                if ('skip' in ev) {
                    if (ev.skip === 'no_guid') model.tally.noGuid++;
                    else model.tally.other++;
                    continue;
                }
                before[ev.source]++;
                addEvent(model, ev, opts);
            }
            const what = [before.sysmon && `${n(before.sysmon, 'Sysmon event')}`, before.ecs && `${n(before.ecs, 'ECS event')}`]
                .filter(Boolean)
                .join(', ');
            read.push(`${name} (${FORMAT_NAMES[format]}${what ? `, ${what}` : ', nothing this pack reads'})`);
        }

        const t = model.tally;
        const events = t.process + t.network + t.dns;
        if (!events) {
            const why = [
                t.noGuid && `${n(t.noGuid, 'event')} had no ProcessGuid or entity_id`,
                unreadableFiles && `${n(unreadableFiles, 'file')} could not be read`,
            ].filter(Boolean);
            return {
                summary: `No Sysmon (events 1, 3, 22) or ECS process, network or DNS events found in ${n(files.length, 'file')}: ${read.join('; ') || 'none read'}${why.length ? `. ${why.join('; ')}` : ''}.`,
                counts: { files: files.length, records: t.records, events: 0, no_guid: t.noGuid },
            };
        }

        // ---- plan, then write in plan order ---------------------------------------------------
        const known = await knownDestinations(ctx);
        const p: Plan = plan(model, known, opts);
        const ids = new Map<string, string>();
        const made = { process: 0, file: 0, ip: 0, domain: 0 };
        let knownHit = 0;
        let refused = 0;
        let firstRefusal = '';
        let infraMissing = false;
        let links = 0;
        let linkFailures = 0;
        let labelsKept = 0;
        const total = p.nodes.length + p.edges.length || 1;
        let done = 0;
        const tick = () => {
            if (++done % 50 === 0) ctx.progress?.set?.({ percent: 60 + Math.round((done / total) * 40), message: `Staging ${done}/${total}` });
        };

        for (const d of p.nodes) {
            if (ctx.signal?.aborted) break;
            tick();
            if (infraMissing && (d.role === 'ip' || d.role === 'domain')) continue;
            try {
                const node = await ctx.graph!.createNode!({ type: d.type, data: d.data });
                ids.set(d.key, String(node.id));
                made[d.role]++;
                if (d.known) knownHit++;
            } catch (err) {
                const msg = err instanceof Error ? err.message : String(err);
                if (TYPE_MISSING.test(msg)) {
                    if (d.role === 'process' || d.role === 'file') {
                        // Nothing this pack writes means anything without the process type, and nothing
                        // has been written yet: processes come first in every unit.
                        return {
                            summary: `The Endpoint type pack is not installed in this project, so no process can be created. Add it from the Marketplace and run again. Read: ${read.join('; ')}.`,
                            counts: { files: files.length, records: t.records, events, processes: 0 },
                        };
                    }
                    infraMissing = true;
                    continue;
                }
                refused++;
                firstRefusal ||= msg;
            }
        }
        // Read after the nodes, whose ids are what the pairs are keyed by: a node this run matched to
        // one already in the project comes back with that node's id.
        const existing = p.edges.length ? await liveEdges(ctx) : new Map<string, LiveEdge>();
        for (const e of p.edges) {
            if (ctx.signal?.aborted) break;
            tick();
            const from = ids.get(e.from);
            const to = ids.get(e.to);
            if (!from || !to) continue;
            const live = existing.get(pairKey(from, to));
            try {
                if (!live) {
                    await ctx.graph!.createEdge!({ from, to, label: e.label, ...(e.data ? { data: e.data } : {}) });
                } else {
                    // A link already in the project is never restated in someone else's words. The
                    // host reads the same wording from a second writer as a second, independent source
                    // for the link and grades it on that — and this pack would only have read the
                    // wording back. So: data only, by id, with no label; and a link that carries no
                    // data (spawned, executed from) is re-asserted only in the pack's own wording,
                    // which is the export agreeing with whoever drew it first.
                    const own = live.label.trim() === e.label;
                    if (!own) labelsKept++;
                    if (e.data) {
                        // This import's summary replaces the last one whole, so the keys it has no
                        // value for are cleared rather than left describing an earlier export. Sent
                        // whether or not it changed: edges() returns no data to compare with, and the
                        // host stages the call only when a key differs, a null matching no value.
                        const data = e.keys ? { ...Object.fromEntries(e.keys.map((k) => [k, null])), ...e.data } : e.data;
                        if (ctx.graph!.updateEdge) await ctx.graph!.updateEdge(live.id, { data });
                        // A host without updateEdge: the live wording with data is the same update.
                        else await ctx.graph!.createEdge!({ from, to, label: live.label, data });
                    } else if (own) {
                        await ctx.graph!.createEdge!({ from, to, label: e.label });
                    }
                }
                links++;
            } catch (err) {
                linkFailures++;
                firstRefusal ||= err instanceof Error ? err.message : String(err);
            }
        }
        ctx.progress?.set?.({ percent: 100 });

        // ---- summary ------------------------------------------------------------------------
        const parts: string[] = [];
        parts.push(
            `${n(made.process, 'process', 'processes')} from ${n(files.length, 'file')}, with ${n(made.ip, 'IP address', 'IP addresses')} and ${n(made.domain, 'domain')} they reached and ${n(made.file, 'executable')} with hashes (${n(links, 'link')})`,
        );
        if (knownHit) parts.push(`${n(knownHit, 'destination')} ${knownHit === 1 ? 'was' : 'were'} already in this project`);
        if (labelsKept) parts.push(`${n(labelsKept, 'link')} already in the project kept ${labelsKept === 1 ? 'its' : 'their'} label`);
        parts.push(`Read: ${read.join('; ')}`);
        const skipped = [
            t.privateSkipped && `${n(t.privateSkipped, 'connection')} to private-network addresses`,
            t.internalNames && `${n(t.internalNames, 'query', 'queries')} for internal names`,
            t.localSkipped && `${n(t.localSkipped, 'loopback, link-local or multicast connection')}`,
            t.reverseLookups && `${n(t.reverseLookups, 'reverse lookup')}`,
            t.addressQueries && `${n(t.addressQueries, 'query', 'queries')} for an address rather than a name`,
            t.invalidNames && `${n(t.invalidNames, 'name')} the Domain type does not accept`,
            t.badAddresses && `${n(t.badAddresses, 'unparseable address', 'unparseable addresses')}`,
            t.noGuid && `${n(t.noGuid, 'event')} with no ProcessGuid or entity_id (a process is identified by it)`,
            p.unnamed && `${n(p.unnamed, 'process', 'processes')} with no image name`,
            unreadablePieces && `${n(unreadablePieces, 'record')} that did not parse`,
            unreadableFiles && `${n(unreadableFiles, 'file')} that could not be read`,
        ].filter(Boolean);
        if (skipped.length) parts.push(`Skipped ${skipped.join(', ')}`);
        if (t.privateSkipped || t.internalNames) {
            parts.push(`Turn on "${INCLUDE_PRIVATE_TITLE}" to import the private-network ones`);
        }
        if (p.trimmed) {
            parts.push(
                `${n(p.trimmed, 'process', 'processes')} reached more than ${CAPS.destinationsPerProcess} destinations; the ones with the most events were kept (destinations_not_imported on the node)`,
            );
        }
        if (p.notImported) {
            const cap =
                p.capHit === 'nodes' ? `${CAPS.nodes.toLocaleString('en-US')} nodes` : p.capHit === 'edges' ? `${CAPS.edges.toLocaleString('en-US')} links` : '3 MB of changes';
            parts.push(
                `${n(p.notImported, 'more process', 'more processes')} not imported: a run stops at ${cap}. Filter the export by host, time or process and run again`,
            );
        }
        if (infraMissing) parts.push('The Infrastructure type pack is not installed, so no address or domain was created');
        if (refused || linkFailures) {
            parts.push(`${n(refused + linkFailures, 'write')} refused (first: ${firstRefusal})`);
        }
        if (ctx.signal?.aborted) parts.push('Stopped before the end; what was staged is kept');
        return {
            summary: `${parts.join('. ')}.`,
            counts: {
                files: files.length,
                records: t.records,
                events,
                processes: made.process,
                ip_addresses: made.ip,
                domains: made.domain,
                executables: made.file,
                links,
                labels_kept: labelsKept,
                known: knownHit,
                private_skipped: t.privateSkipped,
                local_skipped: t.localSkipped,
                no_guid: t.noGuid,
                not_imported: p.notImported,
                refused: refused + linkFailures,
            },
        };
    },
});

// The pack's page in the catalog, in Markdown: the About section the marketplace drawer shows
// below the one-line `summary`. Kept as an array of lines rather than a template literal so the
// Markdown's backticks need no escaping.
const PACK_PAGE = [
    "For bringing a host's own record into the investigation: which process reached which address or domain, what spawned it, and the hash of the file it ran from. It reads exports you already hold: Sysmon events 1, 3 and 22 (wevtutil or Event Viewer XML, Get-WinEvent, Winlogbeat, Velociraptor, EvtxECmd, evtx_dump, a SIEM's CSV) and ECS process, network and DNS events from an EDR such as Elastic Defend. Parsed on this device, nothing looked up: no account, key or cost.",
    '',
    'Filter the export to the hosts and time you are investigating first: a file can be 25 MB at most, and a run stops at 1,500 nodes, taking first the processes that reached infrastructure already in the project.',
    '',
    'Host names, user names and command lines become node fields, so a project on a Vineyard server holds them. For host data that must stay on this machine, use the desktop app in local mode.',
    '',
    '**Read results with care:**',
    '',
    '- A record without a ProcessGuid (or ECS `entity_id`) is skipped, so process lists and netstat tables are not read.',
    '- Loopback, link-local and multicast traffic never comes in; private-network addresses and internal names only when you ask.',
    "- A link's `events`, `ports` and first and last times cover only the last import that saw the pair; a later export replaces them.",
    '- A command line too long for one node is cut to its start, marked `command_line_truncated` with the full `command_line_length`.',
    '',
    '**Source:** https://github.com/Vineyard-Intelligence/pluginpack-host-artifacts (Apache-2.0)',
].join('\n');

export default definePluginPack({
    identifier: 'run.vineyard.pluginpacks.host_artifacts',
    content_type: 'vineyard:pluginpack',
    name: 'Host Artifacts',
    version: PACK_VERSION,
    summary:
        'Imports Sysmon and EDR process, network and DNS events from exports you pick, parsed locally, as processes linked to the addresses and domains they reached and the files they ran from.',
    description: PACK_PAGE,
    plugins: [processActivityImport],
});
