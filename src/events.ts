// Records → the three events this pack imports: a process starting, a process making a network
// connection, and a process asking DNS for a name.
//
// Two vocabularies are read:
//
//   SYSMON — event 1 (process create), 3 (network connection) and 22 (DNS query), by Sysmon's own
//   field names, wherever the export put them: `winlog.event_data` (Winlogbeat), `EventData`
//   (Velociraptor, evtx_dump, event XML), EvtxECmd's `Payload` JSON (KAPE), one column per field
//   (Splunk and most SIEM CSVs), or the rendered message text (`Get-WinEvent`, Event Viewer CSV).
//
//   ECS — Elastic Common Schema process, network and DNS events (Elastic Defend, and any EDR export
//   mapped to ECS), keyed by `process.entity_id`.
//
// Both carry a per-execution process id (ProcessGuid / entity_id), and that is the reason the pack
// reads these and not process lists or netstat tables: endpoint.process is identified by
// (process_guid, process_name, pid), and without the GUID the same image name and PID on two hosts —
// or on one host a week apart — become one process. A record without one is skipped and counted.
// Pure; its one import is net.ts, which is pure too.

import { parseAddress } from './net';

export type EventSource = 'sysmon' | 'ecs';

export interface ProcFields {
    guid?: string;
    pid?: number;
    /** Full image path as logged. */
    image?: string;
    commandLine?: string;
    user?: string;
    integrity?: string;
    startTime?: string;
}

export interface Hashes {
    sha256?: string;
    sha1?: string;
    md5?: string;
    imphash?: string;
}

export interface PeInfo {
    originalFileName?: string;
    company?: string;
    product?: string;
    fileVersion?: string;
    description?: string;
}

interface Base {
    source: EventSource;
    time?: string;
    host?: string;
    proc: ProcFields;
    /**
     * The record closes something another record opened: Elastic Defend logs a connection when it
     * opens and again as `disconnect_received`, and a lookup as `lookup_requested` and then
     * `lookup_result`. Such a record dates the pair like any other but is counted against the
     * opening ones rather than beside them, or every Defend link would say twice what happened.
     */
    closing?: boolean;
}
export interface ProcessEvent extends Base {
    kind: 'process';
    parent?: ProcFields;
    hashes: Hashes;
    pe: PeInfo;
}
export interface NetworkEvent extends Base {
    kind: 'network';
    direction: 'outbound' | 'inbound';
    /** The other end, as logged (not yet canonical). */
    remote: string;
    /** The service port: the destination port in either direction, as Sysmon records it. */
    port?: number;
    protocol?: string;
    remoteHostname?: string;
}
export interface DnsEvent extends Base {
    kind: 'dns';
    query: string;
    /** 0 is success; anything else is the resolver's error code (9003 is NXDOMAIN). */
    status?: string;
    /** Raw answers: addresses and, for a CNAME chain, names. */
    answers: string[];
}
export type HostEvent = ProcessEvent | NetworkEvent | DnsEvent;

/** `other` is a record this pack does not read; `no_guid` is one it would, minus the process id. */
export type SkipReason = 'other' | 'no_guid';
export type Normalized = HostEvent | { skip: SkipReason };

// ---- small readers ---------------------------------------------------------------------------

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => !!v && typeof v === 'object' && !Array.isArray(v);

/**
 * Text the server can store: NUL and unpaired surrogates become U+FFFD, valid pairs stay.
 *
 * The backend refuses a row holding either (Postgres cannot store them), and it refuses it ROW BY
 * ROW at apply time, long after the review: the process lands nowhere and every link to it is held
 * back. Both reach an export easily — `\u0000` and a lone `\ud800` are legal JSON escapes, a
 * numeric XML entity can name either, and Windows allows unpaired surrogates in file names and
 * command lines, which an attacker controls. Every string this pack writes passes through `text`,
 * so cleaning here is cleaning everything.
 */
export function storable(s: string): string {
    return s.replace(/[\ud800-\udbff][\udc00-\udfff]|[\u0000\ud800-\udfff]/g, (m) => (m.length === 2 ? m : '\ufffd'));
}

/** A scalar as trimmed, storable text; '' for anything else. XML-ish `{ "#text": … }` and `{ Value: … }` unwrap. */
function text(v: unknown): string {
    if (v == null) return '';
    if (typeof v === 'string') return storable(v.trim());
    if (typeof v === 'number' || typeof v === 'boolean') return String(v);
    if (isObj(v)) {
        for (const k of ['#text', 'Value', 'value', '#value']) if (k in v) return text(v[k]);
    }
    return '';
}

/** Case-insensitive own-key lookup, so `ProcessGuid`, `processguid` and `PROCESSGUID` all match. */
function lower(o: Obj): Map<string, unknown> {
    const m = new Map<string, unknown>();
    for (const [k, v] of Object.entries(o)) if (!m.has(k.toLowerCase())) m.set(k.toLowerCase(), v);
    return m;
}

/** A dotted ECS path, read as nested objects or as one flat dotted key (Kibana's CSV export). */
function at(o: Obj, path: string): unknown {
    if (path in o) return o[path];
    let cur: unknown = o;
    for (const part of path.split('.')) {
        if (!isObj(cur)) return undefined;
        cur = cur[part];
    }
    return cur;
}

const toInt = (v: unknown): number | undefined => {
    const s = text(v);
    if (!/^\d+$/.test(s)) return undefined;
    const n = Number(s);
    return Number.isSafeInteger(n) ? n : undefined;
};

/**
 * Time → ISO 8601 UTC, or undefined.
 *
 * Sysmon's `UtcTime` (`2026-11-01 12:34:56.789`) is UTC with no marker, and EvtxECmd writes seven
 * fractional digits; both are read as UTC. Epoch numbers are seconds (Velociraptor) or
 * milliseconds; `/Date(…)/` is what `ConvertTo-Json` makes of a DateTime. A local time with no
 * zone (Event Viewer's "Date and Time" column) is not read at all — guessing a zone would move the
 * event by hours — which is why the Sysmon field is always preferred over the wrapper's.
 */
export function toIso(v: unknown): string | undefined {
    if (typeof v === 'number' && Number.isFinite(v)) {
        const ms = v > 1e12 ? v : v * 1000;
        const d = new Date(ms);
        return Number.isNaN(d.getTime()) ? undefined : d.toISOString();
    }
    const s = text(v);
    if (!s) return undefined;
    const ms = /^\/Date\((-?\d+)\)\/$/.exec(s);
    if (ms) return toIso(Number(ms[1]));
    if (/^\d{10}(\.\d+)?$/.test(s) || /^\d{13}$/.test(s)) return toIso(Number(s));
    const m = /^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})(?:\.(\d+))?\s*(Z|[+-]\d{2}:?\d{2})?$/i.exec(s);
    if (!m) return undefined;
    const frac = (m[3] ?? '').slice(0, 3).padEnd(3, '0');
    const zone = !m[4] || m[4].toUpperCase() === 'Z' ? 'Z' : m[4].length === 5 ? `${m[4].slice(0, 3)}:${m[4].slice(3)}` : m[4];
    const d = new Date(`${m[1]}T${m[2]}.${frac}${zone}`);
    return Number.isNaN(d.getTime()) ? undefined : d.toISOString();
}

const GUID_RE = /^\{?([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\}?$/;

/**
 * One spelling per process GUID, or undefined for none.
 *
 * GUIDs are case-insensitive by definition, but `process_guid` compares as written, and exports
 * disagree on case and braces — so a GUID is always written `{lower-case}`, the form Sysmon itself
 * logs. The all-zero GUID is Sysmon's "no parent known" (the System process, early boot) and is
 * treated as absent: keyed on, it would make every orphan the same process. An id that is not
 * GUID-shaped (Elastic Defend's base64 entity_id) is kept exactly as given.
 */
export function canonGuid(v: unknown): string | undefined {
    const s = text(v);
    if (!s) return undefined;
    const m = GUID_RE.exec(s);
    if (!m) return s;
    const g = m[1].toLowerCase();
    return /^[0-]+$/.test(g) ? undefined : `{${g}}`;
}

/** `SHA1=…,MD5=…,SHA256=…,IMPHASH=…` (Sysmon's `Hashes`), plus any per-algorithm fields. */
export function parseHashes(...sources: unknown[]): Hashes {
    const out: Hashes = {};
    const LEN: Record<keyof Hashes, number> = { sha256: 64, sha1: 40, md5: 32, imphash: 32 };
    const put = (alg: string, value: string) => {
        const k = alg.toLowerCase().replace(/[^a-z0-9]/g, '') as keyof Hashes;
        const hex = value.trim().toLowerCase();
        if (k in LEN && !out[k] && hex.length === LEN[k] && /^[0-9a-f]+$/.test(hex)) out[k] = hex;
    };
    for (const src of sources) {
        if (isObj(src)) {
            for (const [k, v] of Object.entries(src)) put(k, text(v));
        } else {
            for (const m of text(src).matchAll(/([A-Za-z0-9]+)=([0-9A-Fa-f]+)/g)) put(m[1], m[2]);
        }
    }
    return out;
}

const basename = (p: string) => p.split(/[\\/]/).filter(Boolean).pop() ?? p;
export { basename };

// ---- Sysmon ----------------------------------------------------------------------------------

/** The rendered message's first line → event id. Sysmon's titles are fixed English strings. */
const TITLES: Record<string, number> = {
    'process create': 1,
    'network connection detected': 3,
    'dns query': 22,
};

/**
 * Sysmon's rendered message: a title line, then `Key: value` per field. Split at the FIRST `: `
 * only, because the value is free text — a command line can hold any number of colons.
 */
export function parseMessage(msg: string): { id?: number; fields: Obj } | null {
    const lines = msg.split(/\r?\n/);
    const title = (lines[0] ?? '').trim().replace(/:$/, '').toLowerCase();
    const fields: Obj = {};
    let n = 0;
    for (const line of lines.slice(1)) {
        const m = /^\s*([A-Za-z][A-Za-z0-9]*):\s?(.*)$/.exec(line);
        if (!m) continue;
        fields[m[1]] = m[2].trim();
        n++;
    }
    if (!n) return null;
    return { id: TITLES[title], fields };
}

/** EventData as XML-to-JSON converters leave it: `{ Data: [{ "@Name": k, "#text": v }, …] }`. */
function fromDataArray(v: unknown): Obj | null {
    const arr = isObj(v) && Array.isArray(v.Data) ? v.Data : Array.isArray(v) ? v : null;
    if (!arr) return null;
    const out: Obj = {};
    for (const d of arr) {
        if (!isObj(d)) continue;
        const name = text(d['@Name'] ?? d.Name ?? (isObj(d['#attributes']) ? d['#attributes'].Name : undefined));
        if (name) out[name] = text(d['#text'] ?? d.Value ?? d.value ?? '');
    }
    return out;
}

/** A field container that may be an object, a Data array, or either one serialized into a string. */
function fieldBag(v: unknown): Obj | null {
    if (typeof v === 'string') {
        const s = v.trim();
        if (!s.startsWith('{') && !s.startsWith('[')) return null;
        try {
            return fieldBag(JSON.parse(s));
        } catch {
            return null;
        }
    }
    if (isObj(v) && isObj(v.EventData)) return fieldBag(v.EventData);
    return fromDataArray(v) ?? (isObj(v) ? v : null);
}

interface SysmonView {
    id?: number;
    fields: Map<string, unknown>;
    host?: string;
    wrapperTime?: unknown;
}

const EVENT_ID_KEYS = ['eventid', 'eventcode', 'event id', 'event_id', 'id'];
const HOST_KEYS = ['computer', 'computername', 'machinename', 'hostname', 'host', 'devicename'];
const TIME_KEYS = ['eventtime', 'timecreated', 'timestamp', '@timestamp', '_time'];

/** Everything a record says in Sysmon's vocabulary, merged from every place an export puts it. */
function sysmonView(rec: Obj): SysmonView | null {
    let r = rec;
    if (isObj(r.Event)) r = r.Event as Obj; // evtx_dump and xml2json put everything under Event
    const top = lower(r);
    const system = isObj(r.System) ? (r.System as Obj) : null;
    const winlog = isObj(r.winlog) ? (r.winlog as Obj) : null;

    // Later sources fill only what earlier ones left blank: structured EventData first, then the
    // record's own columns, then the rendered message — the lossiest, last.
    const fields = new Map<string, unknown>();
    const add = (bag: Obj | null) => {
        if (!bag) return;
        for (const [k, v] of Object.entries(bag)) {
            const key = k.toLowerCase();
            if (!fields.has(key) || text(fields.get(key)) === '') fields.set(key, v);
        }
    };
    add(winlog ? fieldBag(winlog.event_data) : null);
    add(fieldBag(top.get('eventdata')));
    add(fieldBag(top.get('payload')));
    add(r);

    let id: number | undefined;
    const idCandidates = [winlog?.event_id, system?.EventID, ...EVENT_ID_KEYS.map((k) => top.get(k))];
    for (const c of idCandidates) {
        const n = toInt(c);
        if (n != null) {
            id = n;
            break;
        }
    }

    const msg = [top.get('message'), top.get('description'), ...Object.values(r)].find(
        (v) => typeof v === 'string' && /^(Process Create|Network connection detected|Dns query):/i.test(v.trim()),
    );
    if (typeof msg === 'string') {
        const parsed = parseMessage(msg.trim());
        if (parsed) {
            add(parsed.fields);
            id ??= parsed.id;
        }
    }

    const host =
        text(winlog?.computer_name) ||
        text(system?.Computer) ||
        HOST_KEYS.map((k) => text(top.get(k))).find(Boolean) ||
        text(at(r, 'host.name')) ||
        undefined;
    const tc = system?.TimeCreated;
    const wrapperTime =
        (isObj(tc) ? (tc.SystemTime ?? (isObj(tc['#attributes']) ? tc['#attributes'].SystemTime : undefined) ?? tc['@SystemTime']) : tc) ??
        TIME_KEYS.map((k) => top.get(k)).find((v) => text(v) !== '');
    return { id, fields, host, wrapperTime };
}

function procFrom(f: Map<string, unknown>, prefix = ''): ProcFields {
    const g = (k: string) => text(f.get(`${prefix}${k}`.toLowerCase()));
    const out: ProcFields = {};
    const guid = canonGuid(g('ProcessGuid'));
    if (guid) out.guid = guid;
    const pid = toInt(g('ProcessId'));
    if (pid != null) out.pid = pid;
    const image = g('Image');
    if (image && image !== '-') out.image = image;
    const cmd = g('CommandLine');
    if (cmd && cmd !== '-') out.commandLine = cmd;
    const user = g('User');
    if (user && user !== '-') out.user = user;
    return out;
}

const bool = (v: unknown) => /^(true|1|yes)$/i.test(text(v));

function fromSysmon(rec: Obj): Normalized | null {
    const v = sysmonView(rec);
    if (!v || (v.id !== 1 && v.id !== 3 && v.id !== 22)) return null;
    const f = v.fields;
    const has = (k: string) => text(f.get(k)) !== '';
    // The shape check is what tells Sysmon's event 3 from the System log's event 3: no other
    // provider writes these fields under these ids.
    const shaped =
        (v.id === 1 && has('image')) ||
        (v.id === 3 && (has('destinationip') || has('sourceip'))) ||
        (v.id === 22 && has('queryname'));
    if (!shaped) return null;
    const proc = procFrom(f);
    if (!proc.guid) return { skip: 'no_guid' };
    const time = toIso(f.get('utctime')) ?? toIso(v.wrapperTime);
    const base = { source: 'sysmon' as const, time, host: v.host, proc };

    if (v.id === 1) {
        proc.startTime = time;
        const integrity = text(f.get('integritylevel'));
        if (integrity && integrity !== '-') proc.integrity = integrity;
        const parent: ProcFields = {};
        const pg = canonGuid(f.get('parentprocessguid'));
        if (pg) parent.guid = pg;
        const ppid = toInt(f.get('parentprocessid'));
        if (ppid != null) parent.pid = ppid;
        const pimg = text(f.get('parentimage'));
        if (pimg && pimg !== '-') parent.image = pimg;
        const pcmd = text(f.get('parentcommandline'));
        if (pcmd && pcmd !== '-') parent.commandLine = pcmd;
        const puser = text(f.get('parentuser'));
        if (puser && puser !== '-') parent.user = puser;
        const pe: PeInfo = {};
        const peField = (k: string) => {
            const s = text(f.get(k));
            return s && s !== '-' && s !== '?' ? s : undefined;
        };
        pe.originalFileName = peField('originalfilename');
        pe.company = peField('company');
        pe.product = peField('product');
        pe.fileVersion = peField('fileversion');
        pe.description = peField('description');
        return {
            ...base,
            kind: 'process',
            parent: parent.guid ? parent : undefined,
            hashes: parseHashes(f.get('hashes'), {
                sha256: f.get('sha256'),
                sha1: f.get('sha1'),
                md5: f.get('md5'),
                imphash: f.get('imphash'),
            }),
            pe,
        };
    }
    if (v.id === 3) {
        // Sysmon puts the initiator in Source*: an accepted connection has the remote peer there and
        // this host in Destination*. The destination port is the service port either way.
        const inbound = has('initiated') && !bool(f.get('initiated'));
        const remote = text(f.get(inbound ? 'sourceip' : 'destinationip'));
        if (!remote) return { skip: 'other' };
        const rh = text(f.get(inbound ? 'sourcehostname' : 'destinationhostname'));
        return {
            ...base,
            kind: 'network',
            direction: inbound ? 'inbound' : 'outbound',
            remote,
            port: toInt(f.get('destinationport')),
            protocol: text(f.get('protocol')).toLowerCase() || undefined,
            remoteHostname: rh && rh !== '-' ? rh : undefined,
        };
    }
    return {
        ...base,
        kind: 'dns',
        query: text(f.get('queryname')),
        status: text(f.get('querystatus')) || undefined,
        answers: splitAnswers(f.get('queryresults')),
    };
}

/**
 * Sysmon's QueryResults: `type:  5 edge.example.net;::ffff:203.0.113.10;` — `;`-separated, a CNAME
 * as `type:  5 <name>`, an A record as an IPv4-mapped address. Other record types are dropped; the
 * address is turned canonical later, with everything else.
 */
export function splitAnswers(v: unknown): string[] {
    if (Array.isArray(v)) return v.map(text).filter(Boolean);
    const out: string[] = [];
    for (const part of text(v).split(';')) {
        const p = part.trim();
        if (!p || p === '-') continue;
        const typed = /^type:\s*(\d+)\s+(\S+)$/i.exec(p);
        if (typed) {
            if (typed[1] === '5') out.push(typed[2]);
            continue;
        }
        out.push(p);
    }
    return out;
}

// ---- ECS -------------------------------------------------------------------------------------

const list = (v: unknown): string[] => {
    if (Array.isArray(v)) return v.map(text).filter(Boolean);
    const s = text(v);
    if (s.startsWith('[')) {
        try {
            return list(JSON.parse(s));
        } catch {
            /* fall through */
        }
    }
    return s ? s.split(/\s*,\s*/) : [];
};

function ecsProc(r: Obj, base: string): ProcFields {
    const g = (k: string) => text(at(r, `${base}.${k}`));
    const out: ProcFields = {};
    const guid = canonGuid(g('entity_id'));
    if (guid) out.guid = guid;
    const pid = toInt(g('pid'));
    if (pid != null) out.pid = pid;
    const image = g('executable') || g('name');
    if (image) out.image = image;
    const cmd = g('command_line');
    if (cmd) out.commandLine = cmd;
    return out;
}

// ECS spells direction `ingress`/`egress` (and once `inbound`/`outbound`); Elastic Defend writes
// `incoming`/`outgoing`, which is why Elastic's own rules match both. Read as outbound, an incoming
// record has this host's own address as the remote end: a node for the host itself, "connected to"
// from the server that accepted the connection.
const INBOUND = new Set(['inbound', 'ingress', 'incoming']);
const OUTBOUND = new Set(['outbound', 'egress', 'outgoing']);

function ecsInbound(r: Obj, action: string, src: string, dst: string): boolean {
    const dir = text(at(r, 'network.direction')).toLowerCase();
    if (INBOUND.has(dir) || action === 'connection_accepted') return true;
    if (OUTBOUND.has(dir) || action === 'connection_attempted') return false;
    // No direction this pack knows (`internal`, `unknown`, or none): the host's own addresses, which
    // ECS lists in host.ip, tell which end is this machine.
    const own = new Set(list(at(r, 'host.ip')).map((v) => parseAddress(v)?.ip).filter(Boolean));
    const mine = (v: string) => own.has(parseAddress(v)?.ip);
    return !!dst && mine(dst) && !(src && mine(src));
}

function fromEcs(rec: Obj): Normalized | null {
    const r = isObj(rec._source) ? (rec._source as Obj) : rec;
    if (!isObj(r.process) && !Object.keys(r).some((k) => k.startsWith('process.'))) return null;
    const proc = ecsProc(r, 'process');
    const userName = text(at(r, 'user.name'));
    const userDomain = text(at(r, 'user.domain'));
    if (userName) proc.user = userDomain ? `${userDomain}\\${userName}` : userName;
    const categories = list(at(r, 'event.category'));
    const types = list(at(r, 'event.type'));
    const action = text(at(r, 'event.action')).toLowerCase();
    const query = text(at(r, 'dns.question.name'));
    const dst = text(at(r, 'destination.ip'));
    const src = text(at(r, 'source.ip'));
    const isProcessStart =
        categories.includes('process') && (types.includes('start') || /^(start|exec|fork|process_started)$/.test(action));
    if (!query && !dst && !src && !isProcessStart) return null;
    if (!proc.guid) return { skip: 'no_guid' };
    const time = toIso(at(r, '@timestamp')) ?? toIso(at(r, 'event.created'));
    const host = text(at(r, 'host.name')) || text(at(r, 'host.hostname')) || undefined;
    const base = { source: 'ecs' as const, time, host, proc };

    if (query) {
        return {
            ...base,
            kind: 'dns',
            query,
            status: text(at(r, 'dns.response_code')) || undefined,
            answers: list(at(r, 'dns.resolved_ip')),
            ...(action === 'lookup_result' ? { closing: true } : {}),
        };
    }
    if (dst || src) {
        const inbound = ecsInbound(r, action, src, dst);
        const remote = inbound ? src : dst;
        if (!remote) return { skip: 'other' };
        const closing = types.includes('end') || action === 'disconnect_received';
        return {
            ...base,
            kind: 'network',
            direction: inbound ? 'inbound' : 'outbound',
            remote,
            port: toInt(at(r, 'destination.port')),
            protocol: text(at(r, 'network.transport')).toLowerCase() || undefined,
            ...(closing ? { closing: true } : {}),
        };
    }
    proc.startTime = toIso(at(r, 'process.start')) ?? time;
    const parent = ecsProc(r, 'process.parent');
    const pe = (k: string) => text(at(r, `process.pe.${k}`)) || undefined;
    return {
        ...base,
        kind: 'process',
        parent: parent.guid ? parent : undefined,
        // Nested (`process.hash.sha256` as objects) and flat (Kibana's CSV, one dotted column each).
        hashes: parseHashes(at(r, 'process.hash'), {
            sha256: at(r, 'process.hash.sha256'),
            sha1: at(r, 'process.hash.sha1'),
            md5: at(r, 'process.hash.md5'),
            imphash: at(r, 'process.pe.imphash'),
        }),
        pe: {
            originalFileName: pe('original_file_name'),
            company: pe('company'),
            product: pe('product'),
            fileVersion: pe('file_version'),
            description: pe('description'),
        },
    };
}

// ---- entry point -----------------------------------------------------------------------------

/**
 * One record → one event, a counted skip, or `{ skip: 'other' }` for a record this pack does not
 * read. Winlogbeat records carry both vocabularies; Sysmon's is tried first because it is the one
 * the event was written in.
 */
export function normalize(rec: Record<string, unknown>): Normalized {
    let r: Obj = rec;
    // Splunk's JSON export wraps each row as { preview, offset, result: {…} }.
    if (isObj(r.result) && ('preview' in r || 'offset' in r)) r = r.result as Obj;
    if (isObj(r._source)) r = r._source as Obj;
    return fromSysmon(r) ?? fromEcs(r) ?? { skip: 'other' };
}
