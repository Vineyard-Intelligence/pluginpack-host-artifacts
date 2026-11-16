// Events → what goes on the graph, under the run's caps.
//
// Two passes, both pure. `addEvent` folds every event into one record per process (keyed by its
// GUID), with one summary per (process, destination) pair: the backend allows a single edge per
// ordered pair of nodes, so a beacon's thousand connections to one address are one edge carrying a
// count and a time range, never a thousand. `plan` then decides which of those processes fit the
// run and turns them into node and edge drafts the plugin writes in order.

import { parseAddress, parseName } from './net';
import type { AddressClass } from './net';
import { basename } from './events';
import type { EventSource, Hashes, HostEvent, PeInfo, ProcFields } from './events';

export interface Options {
    /** Import destinations on private networks and internal-only names. */
    includePrivate: boolean;
    /** Import processes that made no network connection or DNS query. */
    includeInactive: boolean;
}

/**
 * Bounds on one run. The node and edge caps keep the review readable; the byte budget keeps the
 * change set inside one batch request, which the API refuses above 4 MiB (`BULK_MAX_BYTES`), with
 * room for the request's own framing. A long encoded PowerShell command line is tens of kilobytes,
 * so the byte budget, not the count, is what a noisy host hits first.
 *
 * Bytes are counted as the server counts them (`jsonBytes`), not in UTF-8: a path under a Korean
 * user name is six bytes a character there. Counted in UTF-8, a Korean host's run that reached the
 * budget was a 6 MB request, and the server refused every row of it.
 */
export const CAPS = {
    nodes: 1500,
    edges: 3000,
    bytes: 3 * 1024 * 1024,
    /**
     * One node's data. The server refuses a row over 256 KiB (`GRAPH_DATA_MAX_BYTES`), and refuses
     * it at apply time, so the process would land nowhere and every link to it would be held. Set so
     * that a Windows command line at its 32,767-character maximum is never cut, even in Hangul
     * (about 197 KB); only a Linux one, which can run to megabytes, is.
     */
    nodeBytes: 200 * 1024,
    /** A browser reaches hundreds of hosts; past this the ones with the most events are kept. */
    destinationsPerProcess: 200,
    /** Parent links followed upward from one process. */
    ancestry: 16,
    answers: 20,
    ports: 20,
    hostnames: 5,
};
export type Caps = typeof CAPS;

export interface Tally {
    records: number;
    process: number;
    network: number;
    dns: number;
    /** A Sysmon or ECS event with no process GUID. */
    noGuid: number;
    /** Not an event this pack reads. */
    other: number;
    privateSkipped: number;
    localSkipped: number;
    internalNames: number;
    reverseLookups: number;
    addressQueries: number;
    invalidNames: number;
    badAddresses: number;
}

/**
 * Records for one pair, opening and closing apart (`closing` in events.ts). The pair's `events` is
 * the larger of the two: one per connection or lookup whether the source logs it once (Sysmon) or
 * at both ends (Elastic Defend), and still a count when an export cut by time kept only one end.
 */
interface Counted {
    opens: number;
    closes: number;
}
const eventCount = (c: Counted) => Math.max(c.opens, c.closes);

interface Conn extends Counted {
    ip: string;
    version: 'ipv4' | 'ipv6';
    cls: AddressClass;
    outbound: number;
    inbound: number;
    ports: Set<number>;
    protocols: Set<string>;
    hostnames: Set<string>;
    first?: string;
    last?: string;
    source: EventSource;
}

interface Lookup extends Counted {
    name: string;
    failed: number;
    statuses: Set<string>;
    answers: Set<string>;
    first?: string;
    last?: string;
    source: EventSource;
}

export interface Proc {
    guid: string;
    /** 2: its own process-start event; 1: seen in a connection or query; 0: only as a parent. */
    rank: number;
    fields: ProcFields;
    parentGuid?: string;
    parentPid?: number;
    host?: string;
    hashes: Hashes;
    pe: PeInfo;
    source: EventSource;
    first?: string;
    net: Map<string, Conn>;
    dns: Map<string, Lookup>;
}

export interface Model {
    procs: Map<string, Proc>;
    tally: Tally;
}

export function createModel(): Model {
    return {
        procs: new Map(),
        tally: {
            records: 0,
            process: 0,
            network: 0,
            dns: 0,
            noGuid: 0,
            other: 0,
            privateSkipped: 0,
            localSkipped: 0,
            internalNames: 0,
            reverseLookups: 0,
            addressQueries: 0,
            invalidNames: 0,
            badAddresses: 0,
        },
    };
}

const earlier = (a?: string, b?: string) => (!a ? b : !b ? a : a < b ? a : b);
const later = (a?: string, b?: string) => (!a ? b : !b ? a : a > b ? a : b);

/**
 * Fold `src` into the record for its GUID. A better-ranked sighting overwrites what a weaker one
 * guessed; an equal or weaker one only fills blanks. Image and PID are part of the process's
 * identity, so the process's own start event must win over what a child's event said about it.
 */
function upsert(model: Model, src: ProcFields, rank: number, source: EventSource, host?: string): Proc {
    const guid = src.guid!;
    let p = model.procs.get(guid);
    if (!p) {
        p = { guid, rank: -1, fields: { guid }, hashes: {}, pe: {}, source, net: new Map(), dns: new Map() };
        model.procs.set(guid, p);
    }
    const overwrite = rank > p.rank;
    for (const [k, v] of Object.entries(src) as [keyof ProcFields, unknown][]) {
        if (v === undefined || v === '') continue;
        if (overwrite || p.fields[k] === undefined) (p.fields as Record<string, unknown>)[k] = v;
    }
    if (host && (overwrite || !p.host)) p.host = host;
    if (overwrite) {
        p.rank = rank;
        p.source = source;
    }
    return p;
}

export function addEvent(model: Model, ev: HostEvent, opts: Options): void {
    const t = model.tally;
    if (ev.kind === 'process') {
        t.process++;
        const p = upsert(model, ev.proc, 2, ev.source, ev.host);
        p.first = earlier(p.first, ev.time);
        for (const [k, v] of Object.entries(ev.hashes)) if (v) (p.hashes as Record<string, string>)[k] ??= v;
        for (const [k, v] of Object.entries(ev.pe)) if (v) (p.pe as Record<string, string>)[k] ??= v;
        if (ev.parent?.guid && ev.parent.guid !== p.guid) {
            p.parentGuid = ev.parent.guid;
            p.parentPid = ev.parent.pid;
            upsert(model, ev.parent, 0, ev.source, ev.host);
        }
        return;
    }

    if (ev.kind === 'network') {
        t.network++;
        const a = parseAddress(ev.remote);
        if (!a) {
            t.badAddresses++;
            return;
        }
        if (a.cls === 'local') {
            t.localSkipped++;
            return;
        }
        if (a.cls === 'private' && !opts.includePrivate) {
            t.privateSkipped++;
            return;
        }
        const p = upsert(model, ev.proc, 1, ev.source, ev.host);
        p.first = earlier(p.first, ev.time);
        let c = p.net.get(a.ip);
        if (!c) {
            c = {
                ip: a.ip,
                version: a.version,
                cls: a.cls,
                outbound: 0,
                inbound: 0,
                ports: new Set(),
                protocols: new Set(),
                hostnames: new Set(),
                opens: 0,
                closes: 0,
                source: ev.source,
            };
            p.net.set(a.ip, c);
        }
        if (ev.closing) c.closes++;
        else c.opens++;
        c[ev.direction]++;
        if (ev.port != null) c.ports.add(ev.port);
        if (ev.protocol) c.protocols.add(ev.protocol);
        if (ev.remoteHostname && c.hostnames.size < CAPS.hostnames) c.hostnames.add(ev.remoteHostname);
        c.first = earlier(c.first, ev.time);
        c.last = later(c.last, ev.time);
        return;
    }

    t.dns++;
    const n = parseName(ev.query);
    if (!n) {
        t.invalidNames++;
        return;
    }
    if (n.cls === 'address') {
        t.addressQueries++;
        return;
    }
    if (n.cls === 'reverse') {
        t.reverseLookups++;
        return;
    }
    if (n.cls === 'internal' && !opts.includePrivate) {
        t.internalNames++;
        return;
    }
    // Asked for or not, a name the Domain type's validator refuses cannot become a node: a
    // single-label internal name (`wpad`), or one with an empty label (`a..example`).
    if (!n.valid) {
        t.invalidNames++;
        return;
    }
    const p = upsert(model, ev.proc, 1, ev.source, ev.host);
    p.first = earlier(p.first, ev.time);
    let l = p.dns.get(n.name);
    if (!l) {
        l = { name: n.name, opens: 0, closes: 0, failed: 0, statuses: new Set(), answers: new Set(), source: ev.source };
        p.dns.set(n.name, l);
    }
    if (ev.closing) l.closes++;
    else l.opens++;
    const status = (ev.status ?? '').trim();
    if (status && status !== '0' && status.toUpperCase() !== 'NOERROR') {
        l.failed++;
        l.statuses.add(status);
    }
    for (const raw of ev.answers) {
        if (l.answers.size >= CAPS.answers) break;
        const a = parseAddress(raw);
        const name = a ? null : parseName(raw);
        const v = a ? a.ip : name && name.cls !== 'address' ? name.name : null;
        if (v) l.answers.add(v);
    }
    l.first = earlier(l.first, ev.time);
    l.last = later(l.last, ev.time);
}

// ---- planning --------------------------------------------------------------------------------

export type Role = 'process' | 'file' | 'ip' | 'domain';

export interface NodeDraft {
    key: string;
    role: Role;
    type: string;
    data: Record<string, unknown>;
    /** A destination that was already a node in the project before this run. */
    known?: boolean;
}
export interface EdgeDraft {
    from: string;
    to: string;
    label: string;
    data?: Record<string, unknown>;
    /**
     * Every data key this kind of link can carry, present this time or not. A link the project
     * already holds gets the absent ones as null: commit merges data key by key, so a key the
     * earlier import wrote and this one has no value for (`failed_events` once the name resolves)
     * would otherwise sit beside this import's counts and describe a different export.
     */
    keys?: readonly string[];
}

export interface Plan {
    nodes: NodeDraft[];
    edges: EdgeDraft[];
    /** Processes with activity, or every process when the analyst asked for that. */
    candidates: number;
    /** Candidates left out because the run reached a cap, and which cap it was. */
    notImported: number;
    capHit?: 'nodes' | 'edges' | 'bytes';
    /** Processes whose destinations were cut to `destinationsPerProcess`. */
    trimmed: number;
    /** Candidates that have no image name, which endpoint.process requires. */
    unnamed: number;
}

/**
 * The labels this pack draws on a new link. A link already in the project keeps the label it has,
 * whoever wrote it (main.ts): a different label on an existing pair is a relabel proposal, and an
 * analyst's own wording would come back for review on every import.
 */
export const LABELS = {
    spawned: 'spawned',
    executed: 'executed from',
    connected: 'connected to',
    accepted: 'accepted connection from',
    queried: 'queried',
};

export const knownIp = (ip: string) => `ip:${ip}`;
export const knownName = (name: string) => `d:${name}`;

const hasPath = (image?: string) => !!image && /[\\/]/.test(image);

/**
 * Bytes `v` takes in a request as the backend measures it: Python's `json.dumps` with its default
 * `ensure_ascii`, which writes every UTF-16 unit above 0x7f as a six-byte `\uXXXX` (an astral
 * character as two). JSON.stringify already escapes quotes, backslashes and controls the same way,
 * so only the non-ASCII units differ.
 */
export function jsonBytes(v: unknown): number {
    const s = JSON.stringify(v ?? {});
    let n = s.length;
    for (let i = 0; i < s.length; i++) if (s.charCodeAt(i) > 0x7f) n += 5;
    return n;
}

/** What one UTF-16 unit of a string value costs inside `jsonBytes`. */
function unitBytes(c: number): number {
    if (c > 0x7f) return 6;
    if (c === 0x22 || c === 0x5c) return 2;
    if (c < 0x20) return c === 8 || c === 9 || c === 10 || c === 12 || c === 13 ? 2 : 6;
    return 1;
}

/**
 * Cut `command_line` until the node's data fits `max`, keeping its start (the program and its first
 * arguments, which is what gets read), and say so: `command_line_truncated` and the full
 * `command_line_length`. The command line is the one field that grows without bound — Linux allows
 * about 2 MB of arguments and an ECS export keeps them whole; the rest are paths and names.
 */
function boundCommandLine(d: Record<string, unknown>, max: number): void {
    const cmd = d.command_line;
    if (typeof cmd !== 'string' || jsonBytes(d) <= max) return;
    d.command_line = '';
    d.command_line_truncated = true;
    d.command_line_length = cmd.length;
    let room = max - jsonBytes(d);
    let end = 0;
    for (; end < cmd.length; end++) {
        const b = unitBytes(cmd.charCodeAt(end));
        if (b > room) break;
        room -= b;
    }
    // Never end on the first half of a pair: a lone surrogate is a row the server refuses.
    if (end > 0 && (cmd.charCodeAt(end - 1) & 0xfc00) === 0xd800) end--;
    d.command_line = cmd.slice(0, end);
}

function processData(p: Proc, caps: Caps): Record<string, unknown> | null {
    const f = p.fields;
    if (!f.image) return null;
    const d: Record<string, unknown> = {
        process_name: basename(f.image),
        process_guid: p.guid,
    };
    if (f.pid != null) d.pid = f.pid;
    if (p.parentPid != null) d.parent_pid = p.parentPid;
    if (f.commandLine) d.command_line = f.commandLine;
    if (f.user) d.user = f.user;
    if (f.startTime) d.start_time = f.startTime;
    // Not declared by endpoint.process, which has no host field; the properties panel shows
    // undeclared keys, and without it two hosts' processes cannot be told apart by reading them.
    if (p.host) d.hostname = p.host;
    if (hasPath(f.image)) d.image_path = f.image;
    if (f.integrity) d.integrity_level = f.integrity;
    boundCommandLine(d, caps.nodeBytes);
    return d;
}

function fileKey(p: Proc): string | null {
    const h = p.hashes;
    if (!hasPath(p.fields.image) || !(h.sha256 || h.md5 || h.sha1)) return null;
    return `f:${h.sha256 ?? ''}|${(p.host ?? '').toLowerCase()}|${p.fields.image}`;
}

function fileData(p: Proc): Record<string, unknown> {
    const h = p.hashes;
    const d: Record<string, unknown> = { file_name: basename(p.fields.image!), file_path: p.fields.image };
    if (h.sha256) d.sha256 = h.sha256;
    if (h.md5) d.md5 = h.md5;
    if (p.host) d.hostname = p.host;
    if (h.sha1) d.sha1 = h.sha1;
    if (h.imphash) d.imphash = h.imphash;
    const pe = p.pe;
    if (pe.originalFileName) d.original_file_name = pe.originalFileName;
    if (pe.company) d.company = pe.company;
    if (pe.product) d.product = pe.product;
    if (pe.fileVersion) d.file_version = pe.fileVersion;
    if (pe.description) d.file_description = pe.description;
    return d;
}

const sorted = <T>(s: Set<T>, cmp?: (a: T, b: T) => number) => [...s].sort(cmp);

/** The data keys `connEdge` and `lookupEdge` can write, in the order they write them. */
export const CONN_KEYS = ['source', 'events', 'direction', 'first_seen', 'last_seen', 'ports', 'port_count', 'protocols', 'remote_hostnames'] as const;
export const LOOKUP_KEYS = ['source', 'events', 'first_seen', 'last_seen', 'answers', 'failed_events', 'statuses'] as const;

function connEdge(c: Conn): { label: string; data: Record<string, unknown> } {
    const ports = sorted(c.ports, (a, b) => a - b);
    const data: Record<string, unknown> = {
        source: c.source,
        events: eventCount(c),
        direction: c.outbound && c.inbound ? 'both' : c.outbound ? 'outbound' : 'inbound',
    };
    if (c.first) data.first_seen = c.first;
    if (c.last) data.last_seen = c.last;
    if (ports.length) data.ports = ports.slice(0, CAPS.ports);
    if (ports.length > CAPS.ports) data.port_count = ports.length;
    if (c.protocols.size) data.protocols = sorted(c.protocols);
    // The name the logging host had for the peer (Sysmon's reverse lookup at the time), kept here
    // rather than as the address's reverse_dns, which would overwrite what a DNS pack found.
    if (c.hostnames.size) data.remote_hostnames = sorted(c.hostnames);
    return { label: c.outbound ? LABELS.connected : LABELS.accepted, data };
}

function lookupEdge(l: Lookup): Record<string, unknown> {
    const data: Record<string, unknown> = { source: l.source, events: eventCount(l) };
    if (l.first) data.first_seen = l.first;
    if (l.last) data.last_seen = l.last;
    if (l.answers.size) data.answers = [...l.answers];
    if (l.failed) {
        data.failed_events = Math.min(l.failed, eventCount(l));
        data.statuses = sorted(l.statuses);
    }
    return data;
}

/**
 * A row's framing in the request beside its data, as commit.ts writes it, rounded up. A node row
 * adds a temp_id (a UUID), its type and a type_pack ref, about 150 bytes; an edge row adds two UUID
 * endpoints and the three provenance keys commit stamps on every link (label_source,
 * confidence_source — each `plugin:` and this plugin's id — and confidence), about 280.
 */
const NODE_ROW = 200;
const EDGE_ROW = 320;

/** Order and cut the model into drafts. Deterministic for the same input and the same graph. */
export function plan(model: Model, known: Set<string>, opts: Options, caps: Caps = CAPS): Plan {
    const procs = [...model.procs.values()];
    const destKey = (kind: 'ip' | 'd', v: string) => (kind === 'ip' ? knownIp(v) : knownName(v));
    const touchesKnown = new Map<Proc, boolean>(
        procs.map((p) => [
            p,
            [...p.net.keys()].some((ip) => known.has(knownIp(ip))) || [...p.dns.keys()].some((n) => known.has(knownName(n))),
        ]),
    );
    const isKnown = (p: Proc) => touchesKnown.get(p) === true;
    // A process with no time sorts last ('\uffff' is above every ISO timestamp).
    const byTime = (a: Proc, b: Proc) =>
        (a.first ?? '\uffff').localeCompare(b.first ?? '\uffff') || a.guid.localeCompare(b.guid);

    // What the pack is for comes first: processes that reached something, and among those the ones
    // that reached infrastructure the project already holds — the overlap between this host and
    // the rest of the investigation is the pivot.
    const active = procs.filter((p) => p.net.size || p.dns.size);
    active.sort((a, b) => Number(isKnown(b)) - Number(isKnown(a)) || byTime(a, b));
    const inactive = opts.includeInactive ? procs.filter((p) => p.rank === 2 && !p.net.size && !p.dns.size).sort(byTime) : [];
    const order = [...active, ...inactive];

    const out: Plan = { nodes: [], edges: [], candidates: order.length, notImported: 0, trimmed: 0, unnamed: 0 };
    /** Every node draft already in `out`, by key: one a later unit trims must be found again. */
    const placed = new Map<string, NodeDraft>();
    const linked = new Set<string>();
    let bytes = 0;

    for (let i = 0; i < order.length; i++) {
        const p = order[i];
        const pdata = processData(p, caps);
        if (!pdata) {
            out.unnamed++;
            continue;
        }
        const nodes: NodeDraft[] = [];
        const edges: EdgeDraft[] = [];
        const inUnit = new Set<string>();
        const addNode = (n: NodeDraft) => {
            if (placed.has(n.key) || inUnit.has(n.key)) return;
            inUnit.add(n.key);
            nodes.push(n);
        };
        const addEdge = (e: EdgeDraft) => {
            const k = `${e.from}\u0000${e.to}`;
            if (linked.has(k) || edges.some((x) => x.from === e.from && x.to === e.to)) return;
            edges.push(e);
        };
        const withImage = (q: Proc, qdata: Record<string, unknown>) => {
            addNode({ key: `p:${q.guid}`, role: 'process', type: 'endpoint.process', data: qdata });
            const fk = fileKey(q);
            if (fk) {
                addNode({ key: fk, role: 'file', type: 'endpoint.file', data: fileData(q) });
                addEdge({ from: `p:${q.guid}`, to: fk, label: LABELS.executed });
            }
        };
        withImage(p, pdata);

        // Ancestry, as far as the export knows it: each parent once, the chain stopping at one
        // already placed (its own unit drew the rest), at a parent with no image, or at the cap.
        let child = p;
        for (let depth = 0; depth < caps.ancestry && child.parentGuid; depth++) {
            const parent = model.procs.get(child.parentGuid);
            const qdata = parent && processData(parent, caps);
            if (!parent || !qdata || parent.guid === p.guid) break;
            const seen = placed.has(`p:${parent.guid}`) || inUnit.has(`p:${parent.guid}`);
            if (!seen) withImage(parent, qdata);
            addEdge({ from: `p:${parent.guid}`, to: `p:${child.guid}`, label: LABELS.spawned });
            if (seen) break;
            child = parent;
        }

        // Destinations, the known ones first and then by how often they were reached.
        const dests: Array<{ k: string; known: boolean; events: number; draft: () => void }> = [];
        for (const c of p.net.values()) {
            const k = destKey('ip', c.ip);
            dests.push({
                k,
                known: known.has(k),
                events: eventCount(c),
                draft: () => {
                    addNode({
                        key: k,
                        role: 'ip',
                        type: 'infrastructure.ip_address',
                        data: { ip_address: c.ip, version: c.version },
                        known: known.has(k),
                    });
                    const e = connEdge(c);
                    addEdge({ from: `p:${p.guid}`, to: k, label: e.label, data: e.data, keys: CONN_KEYS });
                },
            });
        }
        for (const l of p.dns.values()) {
            const k = destKey('d', l.name);
            dests.push({
                k,
                known: known.has(k),
                events: eventCount(l),
                draft: () => {
                    addNode({
                        key: k,
                        role: 'domain',
                        type: 'infrastructure.domain',
                        data: { domain_name: l.name },
                        known: known.has(k),
                    });
                    addEdge({ from: `p:${p.guid}`, to: k, label: LABELS.queried, data: lookupEdge(l), keys: LOOKUP_KEYS });
                },
            });
        }
        dests.sort((a, b) => Number(b.known) - Number(a.known) || b.events - a.events || a.k.localeCompare(b.k));
        // The process's node may be an earlier unit's: a child active first draws its parent as an
        // ancestor, and then this unit's own draft is never written. The count goes on whichever
        // draft is written, or the summary would point at a field no node carries.
        const over = dests.length - caps.destinationsPerProcess;
        const earlierDraft = placed.get(`p:${p.guid}`);
        if (over > 0 && !earlierDraft) pdata.destinations_not_imported = over;
        for (const d of dests.slice(0, caps.destinationsPerProcess)) d.draft();

        const unitBytes =
            nodes.reduce((n, x) => n + jsonBytes(x.data) + NODE_ROW, 0) +
            edges.reduce((n, x) => n + jsonBytes(x.data) + jsonBytes(x.label) + EDGE_ROW, 0) +
            (over > 0 && earlierDraft ? jsonBytes({ destinations_not_imported: over }) : 0);
        const capHit =
            out.nodes.length + nodes.length > caps.nodes
                ? 'nodes'
                : out.edges.length + edges.length > caps.edges
                ? 'edges'
                : bytes + unitBytes > caps.bytes
                ? 'bytes'
                : undefined;
        if (capHit) {
            // Stop rather than skip ahead to smaller units: "the first N in this order" is a result
            // the analyst can reason about and continue from; a scattering of whatever fit is not.
            out.capHit = capHit;
            out.notImported = order.slice(i).filter((q) => q.fields.image).length;
            break;
        }
        if (over > 0) {
            out.trimmed++;
            if (earlierDraft) earlierDraft.data.destinations_not_imported = over;
        }
        for (const n of nodes) placed.set(n.key, n);
        for (const e of edges) linked.add(`${e.from}\u0000${e.to}`);
        out.nodes.push(...nodes);
        out.edges.push(...edges);
        bytes += unitBytes;
    }
    return out;
}
