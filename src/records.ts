// Export files → plain records, before anything decides what a record means.
//
// The same Sysmon event reaches an analyst in a dozen wrappers: a JSON array, JSON lines, a CSV
// with one column per field or with the whole event folded into one cell, Windows event XML, or
// `evtx_dump`'s pretty-printed objects with a "Record N" line between them. This module only
// turns bytes into objects; events.ts reads meaning into them. Pure and dependency-free.

export type FileFormat = 'json' | 'json-lines' | 'csv' | 'tsv' | 'xml' | 'empty' | 'unknown';

export interface ReadResult {
    format: FileFormat;
    records: Record<string, unknown>[];
    /** Pieces that looked like records and did not parse (a JSON line cut short, say). */
    unreadable: number;
}

// ---- text ------------------------------------------------------------------------------------

/**
 * Bytes → text, honouring a byte-order mark.
 *
 * Windows PowerShell 5.1 writes UTF-16LE with a BOM from `Out-File` and `>` — the commonest way an
 * analyst saves `Get-WinEvent … | ConvertTo-Json` or `.ToXml()` output — and reading that as UTF-8
 * yields a NUL between every character and no events. Without a BOM, a NUL in most odd positions of
 * the first kilobyte is the same encoding with the mark stripped.
 */
export function decodeText(bytes: Uint8Array): string {
    const dec = (label: string, from = 0) => new TextDecoder(label).decode(bytes.subarray(from));
    if (bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) return dec('utf-8', 3);
    if (bytes[0] === 0xff && bytes[1] === 0xfe) return dec('utf-16le', 2);
    if (bytes[0] === 0xfe && bytes[1] === 0xff) return dec('utf-16be', 2);
    const probe = Math.min(bytes.length, 1024);
    let oddNul = 0;
    let evenNul = 0;
    for (let i = 0; i < probe; i++) {
        if (bytes[i] !== 0) continue;
        if (i % 2) oddNul++;
        else evenNul++;
    }
    if (probe >= 8 && oddNul > probe / 4 && evenNul === 0) return dec('utf-16le');
    if (probe >= 8 && evenNul > probe / 4 && oddNul === 0) return dec('utf-16be');
    return dec('utf-8');
}

// ---- JSON ------------------------------------------------------------------------------------

const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);

/** Keys an event record has and a wrapper around records does not. */
const EVENT_KEYS = new Set(['message', 'id', 'eventid', 'eventcode', 'system', 'event', 'eventdata', 'winlog', 'process', '@timestamp']);

/**
 * A parsed JSON document → its records.
 *
 * An array is its records. An object is usually a wrapper around them — Elasticsearch's
 * `hits.hits`, or a tool's `{ "rows": [...] }` — so the largest array of objects within two levels
 * is taken; an object with no such array is one record.
 */
function recordsOf(doc: unknown): Record<string, unknown>[] {
    if (Array.isArray(doc)) return doc.filter(isObj);
    if (!isObj(doc)) return [];
    // A lone event is an object too, and it holds arrays of objects of its own: one event from
    // `Get-WinEvent | ConvertTo-Json` carries `Properties: [{ Value }, …]`, which the search below
    // would take for the records. A wrapper (`hits`, `rows`, `result`) has none of these keys.
    if (Object.keys(doc).some((k) => EVENT_KEYS.has(k.toLowerCase()))) return [doc];
    let best: Record<string, unknown>[] | null = null;
    const consider = (v: unknown) => {
        if (!Array.isArray(v)) return;
        const objs = v.filter(isObj);
        if (objs.length && (!best || objs.length > best.length)) best = objs;
    };
    for (const v of Object.values(doc)) {
        consider(v);
        if (isObj(v)) for (const w of Object.values(v)) consider(w);
    }
    return best ?? [doc];
}

/**
 * Every top-level `{…}` in a text that is not one JSON document: JSON lines, objects concatenated
 * with or without commas, `evtx_dump -o json` (pretty objects separated by "Record N" lines), and
 * an array cut off mid-way. Braces inside strings are skipped by tracking quotes and escapes, so a
 * command line full of `{` does not end an object early.
 */
function scanObjects(text: string): { records: Record<string, unknown>[]; unreadable: number } {
    const records: Record<string, unknown>[] = [];
    let unreadable = 0;
    let depth = 0;
    let start = -1;
    let inStr = false;
    let esc = false;
    for (let i = 0; i < text.length; i++) {
        const c = text.charCodeAt(i);
        if (inStr) {
            if (esc) esc = false;
            else if (c === 0x5c) esc = true; // backslash
            else if (c === 0x22) inStr = false; // quote
            continue;
        }
        if (depth > 0 && c === 0x22) {
            inStr = true;
        } else if (c === 0x7b) {
            if (depth++ === 0) start = i;
        } else if (c === 0x7d && depth > 0) {
            if (--depth === 0) {
                try {
                    const v = JSON.parse(text.slice(start, i + 1));
                    if (isObj(v)) records.push(v);
                } catch {
                    unreadable++;
                }
            }
        }
    }
    if (depth > 0) unreadable++; // the file ends inside an object
    return { records, unreadable };
}

// ---- CSV -------------------------------------------------------------------------------------

/** RFC 4180: quoted fields may hold the delimiter, doubled quotes and line breaks. */
export function parseDelimited(text: string, delim: string): string[][] {
    const rows: string[][] = [];
    let row: string[] = [];
    let field = '';
    let quoted = false;
    for (let i = 0; i < text.length; i++) {
        const c = text[i];
        if (quoted) {
            if (c === '"') {
                if (text[i + 1] === '"') {
                    field += '"';
                    i++;
                } else quoted = false;
            } else field += c;
            continue;
        }
        if (c === '"' && field === '') quoted = true;
        else if (c === delim) {
            row.push(field);
            field = '';
        } else if (c === '\n' || c === '\r') {
            if (c === '\r' && text[i + 1] === '\n') i++;
            row.push(field);
            rows.push(row);
            row = [];
            field = '';
        } else field += c;
    }
    if (field !== '' || row.length) {
        row.push(field);
        rows.push(row);
    }
    return rows;
}

/** The delimiter the header line uses most, counting only outside quotes. */
function sniffDelimiter(text: string): string {
    const hint = /^sep=(.)\r?\n/i.exec(text);
    if (hint) return hint[1];
    const end = text.search(/\r?\n/);
    const line = end < 0 ? text : text.slice(0, end);
    let quoted = false;
    const counts: Record<string, number> = { ',': 0, '\t': 0, ';': 0 };
    for (const c of line) {
        if (c === '"') quoted = !quoted;
        else if (!quoted && c in counts) counts[c]++;
    }
    return Object.entries(counts).sort((a, b) => b[1] - a[1])[0][0];
}

function csvRecords(text: string, delim: string): Record<string, unknown>[] {
    const rows = parseDelimited(text, delim);
    // Excel's delimiter hint (`sep=,`) is a line of its own above the header.
    if (rows.length && rows[0].length <= 2 && /^sep=.?$/i.test(rows[0].join(delim))) rows.shift();
    if (rows.length < 2) return [];
    const seen = new Map<string, number>();
    const header = rows[0].map((h, i) => {
        // Event Viewer's CSV export leaves the message column without a header.
        let name = h.trim() || `column_${i + 1}`;
        const n = seen.get(name) ?? 0;
        seen.set(name, n + 1);
        if (n) name = `${name}_${n + 1}`;
        return name;
    });
    const out: Record<string, unknown>[] = [];
    for (const r of rows.slice(1)) {
        if (r.every((v) => v.trim() === '')) continue;
        const rec: Record<string, unknown> = {};
        r.forEach((v, i) => {
            rec[header[i] ?? `column_${i + 1}`] = v;
        });
        out.push(rec);
    }
    return out;
}

// ---- Windows event XML -----------------------------------------------------------------------

const ENTITIES: Record<string, string> = { lt: '<', gt: '>', amp: '&', quot: '"', apos: "'" };

export function decodeXml(s: string): string {
    return s.replace(/&(#x[0-9a-fA-F]+|#\d+|[a-zA-Z]+);/g, (m, e: string) => {
        if (e[0] === '#') {
            const cp = e[1] === 'x' || e[1] === 'X' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
            return Number.isFinite(cp) && cp >= 0 && cp <= 0x10ffff ? String.fromCodePoint(cp) : m;
        }
        return ENTITIES[e] ?? m;
    });
}

const attr = (tagSrc: string, name: string): string | undefined => {
    const m = new RegExp(`\\s${name}\\s*=\\s*(["'])([\\s\\S]*?)\\1`).exec(tagSrc);
    return m ? decodeXml(m[2]) : undefined;
};

/**
 * `<Event>` elements → records shaped like the XML (`System`, `EventData`).
 *
 * A pattern reader, not an XML parser, and that is enough for this input: it is machine-written
 * (`wevtutil qe /f:xml`, Event Viewer's "Save as XML", `.ToXml()`), with a fixed schema and no
 * nesting of the elements read here. A worker has no DOMParser to do better with.
 */
function xmlRecords(text: string): Record<string, unknown>[] {
    const out: Record<string, unknown>[] = [];
    for (const m of text.matchAll(/<Event[\s>][\s\S]*?<\/Event>/g)) {
        const ev = m[0];
        const system: Record<string, unknown> = {};
        const id = /<EventID(?:\s[^>]*)?>\s*(\d+)\s*<\/EventID>/.exec(ev);
        if (id) system.EventID = id[1];
        const prov = /<Provider\s[^>]*>/.exec(ev);
        if (prov) system.Provider = { Name: attr(prov[0], 'Name') };
        const tc = /<TimeCreated\s[^>]*>/.exec(ev);
        if (tc) system.TimeCreated = { SystemTime: attr(tc[0], 'SystemTime') };
        const comp = /<Computer>([\s\S]*?)<\/Computer>/.exec(ev);
        if (comp) system.Computer = decodeXml(comp[1]);
        const chan = /<Channel>([\s\S]*?)<\/Channel>/.exec(ev);
        if (chan) system.Channel = decodeXml(chan[1]);
        const data: Record<string, string> = {};
        for (const d of ev.matchAll(/<Data\s+Name\s*=\s*(["'])([\s\S]*?)\1\s*(?:\/>|>([\s\S]*?)<\/Data>)/g)) {
            data[decodeXml(d[2])] = decodeXml(d[3] ?? '');
        }
        out.push({ System: system, EventData: data });
    }
    return out;
}

// ---- entry point -----------------------------------------------------------------------------

export function readRecords(text: string): ReadResult {
    // A byte-order mark left by a decoder that kept it. Written as an escape, as every invisible
    // character in this source is: one typed literally is one an auditor reading the code cannot see.
    const t = text.replace(/^\ufeff/, '');
    const head = t.trimStart();
    if (!head) return { format: 'empty', records: [], unreadable: 0 };
    if (head[0] === '<') {
        const records = xmlRecords(t);
        return { format: records.length ? 'xml' : 'unknown', records, unreadable: 0 };
    }
    if (head[0] === '[' || head[0] === '{') {
        try {
            return { format: 'json', records: recordsOf(JSON.parse(t)), unreadable: 0 };
        } catch {
            const { records, unreadable } = scanObjects(t);
            return { format: 'json-lines', records, unreadable };
        }
    }
    // `evtx_dump -o json` opens with "Record 1" before the first object.
    if (/^Record \d+\s*\r?\n\s*\{/.test(head)) {
        const { records, unreadable } = scanObjects(t);
        return { format: 'json-lines', records, unreadable };
    }
    const delim = sniffDelimiter(t);
    return { format: delim === '\t' ? 'tsv' : 'csv', records: csvRecords(t, delim), unreadable: 0 };
}
