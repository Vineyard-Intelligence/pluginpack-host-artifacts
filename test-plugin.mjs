#!/usr/bin/env node
/**
 * Tests for the pack: `node test-plugin.mjs` (after build.mjs and gen-manifest.mjs).
 *
 * Two halves, no network and no framework:
 *
 *   1. The pure parsers (addresses, names, times, GUIDs, CSV, JSON lines, event XML), reached through
 *      test/pure.ts bundled with the same pinned esbuild into .test-build/.
 *   2. The REAL dist/pack.mjs — the bundle the registry serves — run against an in-memory host that
 *      refuses and de-duplicates the way the app does, using the type packs' own definitions: the
 *      required fields, the validators, `identity_properties` and `case_insensitive`. A mock with
 *      its own idea of identity would pass a pack that splits or merges processes in production.
 *
 * The type packs are read from HOST_ARTIFACTS_TYPEPACKS, or else from the nearest
 * typepack-basic/typepacks above this file (the main checkout and a worktree both sit under the
 * vineyard root). The fixtures are synthetic; test/make-fixtures.mjs says how they were made.
 */
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const fixture = (name) => readFileSync(join(here, 'test', 'fixtures', name));

let passed = 0;
let failed = 0;
async function test(name, fn) {
    try {
        await fn();
        passed++;
        console.log(`  ✓ ${name}`);
    } catch (e) {
        failed++;
        console.error(`  ✗ ${name}\n      ${String(e?.stack ?? e).split('\n').slice(0, 6).join('\n      ')}`);
    }
}

// ---- 1. pure modules -------------------------------------------------------------------------

mkdirSync(join(here, '.test-build'), { recursive: true });
execFileSync(
    'npx',
    [
        '--yes',
        'esbuild@0.25.12',
        join(here, 'test', 'pure.ts'),
        '--bundle',
        '--format=esm',
        '--platform=node',
        '--target=node20',
        '--log-level=warning',
        `--outfile=${join(here, '.test-build', 'pure.mjs')}`,
    ],
    { stdio: 'inherit', cwd: here },
);
const P = await import(pathToFileURL(join(here, '.test-build', 'pure.mjs')).href);

console.log('pure modules');

await test('addresses: one canonical spelling per address, and the right class', () => {
    const ip = (s) => P.parseAddress(s);
    assert.deepEqual(ip('203.0.113.45'), { ip: '203.0.113.45', version: 'ipv4', cls: 'public' });
    // Sysmon writes an A record IPv4-mapped; it must land on the same node as the dotted quad.
    assert.equal(ip('::ffff:203.0.113.45').ip, '203.0.113.45');
    assert.equal(ip('::FFFF:203.0.113.45').version, 'ipv4');
    assert.equal(ip('2001:0db8:0000:0000:0000:ff00:0042:8329').ip, '2001:db8::ff00:42:8329');
    assert.equal(ip('2001:DB8::FF00:42:8329').ip, '2001:db8::ff00:42:8329');
    assert.equal(ip('2001:db8:0:0:1:0:0:77').ip, '2001:db8::1:0:0:77', 'first of two equal zero runs is compressed');
    assert.equal(ip('2001:db8:0:1:1:1:1:1').ip, '2001:db8:0:1:1:1:1:1', 'a single zero group is not compressed');
    assert.equal(ip('[2001:db8::1]').ip, '2001:db8::1');
    assert.equal(ip('fe80::1%12').cls, 'local');
    for (const local of ['127.0.0.1', '0.0.0.0', '169.254.10.1', '224.0.0.252', '255.255.255.255', '::1', '::', 'ff02::1:3']) {
        assert.equal(ip(local)?.cls, 'local', local);
    }
    for (const priv of ['10.20.0.5', '172.16.0.1', '172.31.255.255', '192.168.1.1', '100.64.0.1', 'fd00::1', 'fc00::1']) {
        assert.equal(ip(priv)?.cls, 'private', priv);
    }
    for (const pub of ['172.15.0.1', '172.32.0.1', '100.128.0.1', '8.8.8.8', '2606:4700::1111']) {
        assert.equal(ip(pub)?.cls, 'public', pub);
    }
    for (const bad of ['', '-', '256.1.1.1', '1.2.3', '01.2.3.4', '1::2::3', '12345::1', 'example.com', '1:2:3:4:5:6:7:8:9']) {
        assert.equal(ip(bad), null, bad);
    }
});

await test('names: lower case, no trailing dot, and the classes a query can fall in', () => {
    const nm = (s) => P.parseName(s);
    assert.deepEqual(nm('Update-Check.Example.NET.'), { name: 'update-check.example.net', cls: 'public', valid: true });
    assert.equal(nm('wpad').cls, 'internal');
    assert.equal(nm('wpad').valid, false, 'a single label is not a Domain');
    assert.equal(nm('nas.home').cls, 'internal');
    assert.equal(nm('nas.home').valid, true);
    assert.equal(nm('dc01.corp.local').cls, 'internal');
    assert.equal(nm('45.113.0.203.in-addr.arpa').cls, 'reverse');
    assert.equal(nm('203.0.113.45').cls, 'address');
    assert.equal(nm('xn--80ak6aa92e.xn--p1ai').cls, 'invalid', 'the Domain validator takes letters-only TLDs');
    assert.equal(nm('_ldap._tcp.example.com').cls, 'public');
});

await test('times: Sysmon UtcTime, EvtxECmd seven digits, epochs and /Date()/ all become ISO UTC', () => {
    assert.equal(P.toIso('2026-11-04 01:12:09.441'), '2026-11-04T01:12:09.441Z');
    assert.equal(P.toIso('2026-11-04 01:12:09.4410000'), '2026-11-04T01:12:09.441Z');
    assert.equal(P.toIso('2026-11-04T01:12:09.4410000Z'), '2026-11-04T01:12:09.441Z');
    assert.equal(P.toIso('2026-11-04T10:12:09.441+09:00'), '2026-11-04T01:12:09.441Z');
    assert.equal(P.toIso('2026-11-04T10:12:09+0900'), '2026-11-04T01:12:09.000Z');
    assert.equal(P.toIso('/Date(1793754729441)/'), '2026-11-04T01:12:09.441Z');
    assert.equal(P.toIso(1793754729.441), '2026-11-04T01:12:09.441Z');
    assert.equal(P.toIso(1793754729441), '2026-11-04T01:12:09.441Z');
    // A local time with no zone is not guessed at.
    assert.equal(P.toIso('11/4/2026 10:12:09 AM'), undefined);
    assert.equal(P.toIso('Nov 4, 2026 @ 03:20:40.700'), undefined);
});

await test('GUIDs: braces and lower case, the zero GUID is absent, other ids kept verbatim', () => {
    assert.equal(P.canonGuid('{4F3A1C2E-2D13-6729-5102-000000001C00}'), '{4f3a1c2e-2d13-6729-5102-000000001c00}');
    assert.equal(P.canonGuid('4f3a1c2e-2d13-6729-5102-000000001c00'), '{4f3a1c2e-2d13-6729-5102-000000001c00}');
    assert.equal(P.canonGuid('{00000000-0000-0000-0000-000000000000}'), undefined);
    assert.equal(P.canonGuid(''), undefined);
    assert.equal(P.canonGuid('NzY0NTMy=='), 'NzY0NTMy==');
});

await test('Sysmon Hashes, rendered messages and QueryResults', () => {
    const h = P.parseHashes('SHA1=AA' + 'a'.repeat(38) + ',MD5=' + 'B'.repeat(32) + ',SHA256=' + 'C'.repeat(64) + ',IMPHASH=' + 'd'.repeat(32));
    assert.deepEqual(h, { sha1: 'aa' + 'a'.repeat(38), md5: 'b'.repeat(32), sha256: 'c'.repeat(64), imphash: 'd'.repeat(32) });
    assert.deepEqual(P.parseHashes('SHA256=abc'), {}, 'a wrong-length digest is dropped');
    const m = P.parseMessage('Process Create:\r\nUtcTime: 2026-11-04 01:10:02.117\r\nCommandLine: cmd /c echo a: b: c\r\nImage: C:\\x.exe');
    assert.equal(m.id, 1);
    assert.equal(m.fields.CommandLine, 'cmd /c echo a: b: c', 'split at the first colon only');
    assert.deepEqual(P.splitAnswers('type:  5 edge-1.example.org;::ffff:203.0.113.45;type:  12 x.example;'), [
        'edge-1.example.org',
        '::ffff:203.0.113.45',
    ]);
    assert.deepEqual(P.splitAnswers('-'), []);
});

await test('readers: CSV quoting, JSON lines with braces in strings, evtx_dump separators, XML entities', () => {
    const csv = P.readRecords('a,b,c\r\n1,"two, ""quoted""\r\nlines",3\r\n\r\n4,5,6\r\n');
    assert.equal(csv.format, 'csv');
    assert.deepEqual(csv.records, [
        { a: '1', b: 'two, "quoted"\r\nlines', c: '3' },
        { a: '4', b: '5', c: '6' },
    ]);
    assert.equal(P.readRecords('a\tb\n1\t2\n').format, 'tsv');
    const jl = P.readRecords('{"cmd":"echo }{ \\" {"}\n{"x":1}\n{"broken":\n');
    assert.equal(jl.format, 'json-lines');
    assert.equal(jl.records.length, 2);
    assert.equal(jl.records[0].cmd, 'echo }{ " {');
    assert.equal(jl.unreadable, 1, 'the cut-off last line is counted');
    const dump = P.readRecords('Record 1\n{\n  "a": 1\n}\nRecord 2\n{\n  "a": 2\n}\n');
    assert.deepEqual(dump.records, [{ a: 1 }, { a: 2 }]);
    const wrapped = P.readRecords(JSON.stringify({ took: 3, hits: { total: 2, hits: [{ _source: { a: 1 } }, { _source: { a: 2 } }] } }));
    assert.equal(wrapped.records.length, 2, "Elasticsearch's hits.hits");
    const xml = P.readRecords(
        "<Events><Event xmlns='x'><System><EventID>1</EventID><Computer>H</Computer></System><EventData><Data Name='CommandLine'>a &amp;&amp; b &lt;c&gt; &#x41;</Data><Data Name='Empty'/></EventData></Event></Events>",
    );
    assert.equal(xml.format, 'xml');
    assert.deepEqual(xml.records[0].EventData, { CommandLine: 'a && b <c> A', Empty: '' });
    assert.equal(P.readRecords('   ').format, 'empty');
    // One event on its own is a record, not a wrapper around its Properties array.
    const one = P.readRecords(JSON.stringify({ Id: 3, Message: 'Network connection detected:', Properties: [{ Value: 1 }, { Value: 2 }] }));
    assert.equal(one.records.length, 1);
    assert.equal(one.records[0].Id, 3);
    assert.deepEqual(P.readRecords('sep=;\r\na;b\r\n1;2\r\n').records, [{ a: '1', b: '2' }], "Excel's sep= line");
});

await test('decoding: UTF-16 with and without a byte-order mark, UTF-8 with one', () => {
    const s = 'Process Create:\r\nImage: C:\\Windows\\주문서.exe';
    const le = Buffer.from(s, 'utf16le');
    assert.equal(P.decodeText(new Uint8Array(Buffer.concat([Buffer.from([0xff, 0xfe]), le]))), s);
    assert.equal(P.decodeText(new Uint8Array(le)), s);
    const be = Buffer.from(le).swap16();
    assert.equal(P.decodeText(new Uint8Array(Buffer.concat([Buffer.from([0xfe, 0xff]), be]))), s);
    assert.equal(P.decodeText(new Uint8Array(Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(s)]))), s);
});

await test('plan: stops at a cap rather than skipping ahead, and ranks known destinations first', () => {
    const opts = { includePrivate: false, includeInactive: false };
    const m = P.createModel();
    for (let i = 0; i < 10; i++) {
        P.addEvent(
            m,
            {
                kind: 'network',
                source: 'sysmon',
                time: `2026-11-04T01:00:0${i}.000Z`,
                proc: { guid: `{00000000-0000-0000-0000-00000000000${i}}`, pid: 100 + i, image: `C:\\p${i}.exe` },
                direction: 'outbound',
                remote: `203.0.113.${i + 1}`,
                port: 443,
            },
            opts,
        );
    }
    const caps = { ...P.CAPS, nodes: 6 };
    const plain = P.plan(m, new Set(), opts, caps);
    assert.equal(plain.nodes.length, 6);
    assert.equal(plain.capHit, 'nodes');
    assert.equal(plain.notImported, 7);
    assert.ok(plain.nodes.some((n) => n.data.ip_address === '203.0.113.1'), 'the earliest goes first');
    const ranked = P.plan(m, new Set([P.knownIp('203.0.113.10')]), opts, caps);
    assert.ok(ranked.nodes.some((n) => n.data.ip_address === '203.0.113.10' && n.known), 'a known destination jumps the queue');
});

// ---- 2. the built pack against a host that behaves like the app -------------------------------

console.log('\nthe built pack');

function findTypepacks() {
    if (process.env.HOST_ARTIFACTS_TYPEPACKS) return process.env.HOST_ARTIFACTS_TYPEPACKS;
    for (let dir = here; ; dir = dirname(dir)) {
        const cand = join(dir, 'typepack-basic', 'typepacks');
        if (existsSync(join(cand, 'endpoint.json'))) return cand;
        if (dirname(dir) === dir) return null;
    }
}
const TP_DIR = findTypepacks();
if (!TP_DIR) {
    console.error('typepack-basic/typepacks not found — set HOST_ARTIFACTS_TYPEPACKS');
    process.exit(1);
}
const ALL_TYPES = {};
for (const f of ['endpoint', 'infrastructure']) {
    for (const ty of JSON.parse(readFileSync(join(TP_DIR, `${f}.json`), 'utf8')).types) ALL_TYPES[`${ty.category}.${ty.name}`] = ty;
}

// validate-node.ts, ported: declared properties only, blanks absent, required on create.
const STRING_TYPES = new Set(['string', 'text', 'hash', 'color', 'url', 'email', 'ip', 'date', 'datetime']);
function validate(types, type, data) {
    const def = types[type];
    if (!def) return `type "${type}" is not defined by any installed typepack. Call list_node_types and use one of the types it returns.`;
    const problems = [];
    for (const [k, v] of Object.entries(data)) {
        const p = def.properties?.[k];
        if (!p || v == null || v === '') continue;
        if (STRING_TYPES.has(p.type) && typeof v !== 'string') problems.push(`${k} is declared ${p.type} but got ${typeof v}`);
        if (p.type === 'integer' && !Number.isInteger(v)) problems.push(`${k} is declared integer but got ${v}`);
        if (p.type === 'enum' && p.enum?.length && !p.enum.includes(v)) problems.push(`${k} must be one of ${p.enum}`);
        if (p.validator?.regex && typeof v === 'string' && !new RegExp(p.validator.regex).test(v)) problems.push(`${k} does not match: ${v}`);
        if (typeof v === 'number' && p.validator?.min != null && v < p.validator.min) problems.push(`${k} below min`);
    }
    for (const [k, p] of Object.entries(def.properties ?? {})) {
        if (p.optional === false && (data[k] == null || data[k] === '')) problems.push(`${k} is required and was not set`);
    }
    return problems.length ? `${type}: ${problems.join('; ')}` : null;
}

// type-visuals.tsx nodeIdentityValue, ported: identity_properties with case folding, else the label.
function identity(types, type, data) {
    const def = types[type];
    if (!def) return null;
    const fold = (k, v) => (def.properties?.[k]?.case_insensitive ? String(v).toLowerCase() : String(v));
    if (def.identity_properties?.length) {
        const parts = def.identity_properties.map((k) => (data[k] == null ? '' : fold(k, data[k])));
        if (parts.some((p) => p !== '')) return `${type}|${parts.join('\\u001f')}`;
    }
    const lp = def.label_property;
    if (lp && data[lp] != null && data[lp] !== '') return `${type}|${fold(lp, data[lp])}`;
    return null;
}

// The backend's has_unstorable_text, which refuses a row at apply time: NUL, or a surrogate that is
// not half of a pair (Python sees a valid pair as one code point).
const UNSTORABLE = /[\ud800-\udbff][\udc00-\udfff]|[\u0000\ud800-\udfff]/g;
function unstorable(v) {
    if (typeof v === 'string') return [...v.matchAll(UNSTORABLE)].some((m) => m[0].length === 1);
    if (Array.isArray(v)) return v.some(unstorable);
    if (v && typeof v === 'object') return Object.entries(v).some(([k, x]) => unstorable(k) || unstorable(x));
    return false;
}

// What the backend measures a node's or an edge's `data`, and a whole batch request, by: Python's
// json.dumps with its default ensure_ascii, so every UTF-16 unit above 0x7f is a six-byte \uXXXX
// escape (an astral character is two). Written here rather than imported from the pack, so a wrong
// rule in the pack cannot also be the rule it is tested against.
const pyBytes = (v) =>
    JSON.stringify(v ?? {}).replace(/[\u0080-\uffff]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`).length;
const GRAPH_DATA_MAX_BYTES = 256 * 1024; // backend core/serializers.py, per row, at apply time
const BULK_MAX_BYTES = 4 * 1024 * 1024; // backend core/bulk.py, per batch-changes request

function makeHost({ types = ALL_TYPES } = {}) {
    const live = { nodes: new Map(), edges: [] };
    let seq = 0;
    const merge = (a, b) => {
        const out = { ...a };
        for (const [k, v] of Object.entries(b)) if (v != null && v !== '') out[k] = v;
        return out;
    };
    // `writer` is what commit stamps as the edge's label_source (labelSourceForRun): `plugin:<id>`
    // for a plugin. A seed run that only creates nodes needs none.
    function newRun(writer = 'analyst') {
        const staged = { creates: [], updates: [], edges: [], edgeUpdates: [] };
        const byIdentity = new Map();
        const graph = {
            async list() {
                return { nodes: [...live.nodes.values()].map((n) => ({ id: n.id, type: n.type, data: { ...n.data } })) };
            },
            async get(id) {
                return live.nodes.get(id) ?? staged.creates.find((n) => n.id === id) ?? null;
            },
            // host-bridge's toEdge: id, ends and label, no data.
            async edges() {
                return live.edges.map((e) => ({ id: e.id, from_node_id: e.from, to_node_id: e.to, label: e.label }));
            },
            async createNode(d) {
                const problem = validate(types, d.type, d.data);
                if (problem) throw new Error(problem);
                if (unstorable(d.data)) throw new Error(`${d.type}: data contains a NUL character or an unpaired surrogate`);
                // The backend refuses this row at apply time, long after the review; refused here so a
                // test sees it as a refusal rather than as a node that would never land.
                const bytes = pyBytes(d.data);
                if (bytes > GRAPH_DATA_MAX_BYTES) throw new Error(`${d.type}: data is ${bytes} bytes, over the ${GRAPH_DATA_MAX_BYTES} byte limit`);
                const k = identity(types, d.type, d.data);
                if (k) {
                    const cached = byIdentity.get(k);
                    if (cached) {
                        Object.assign(cached.data, merge(cached.data, d.data));
                        return cached;
                    }
                    for (const n of live.nodes.values()) {
                        if (identity(types, n.type, n.data) !== k) continue;
                        const merged = merge(n.data, d.data);
                        if (JSON.stringify(merged) !== JSON.stringify(n.data)) staged.updates.push({ id: n.id, data: d.data });
                        const view = { id: n.id, type: n.type, data: merged };
                        byIdentity.set(k, view);
                        return view;
                    }
                }
                const node = { id: `staged_${++seq}`, type: d.type, data: { ...d.data } };
                staged.creates.push(node);
                if (k) byIdentity.set(k, node);
                return node;
            },
            async createEdge(e) {
                for (const r of ['confidence', 'confidence_source', 'label_source', 'corroborated_by']) {
                    if (e.data && r in e.data) throw new Error(`createEdge: ${r} is set by the host`);
                }
                if (unstorable(e.data) || unstorable(e.label)) throw new Error('createEdge: a NUL character or an unpaired surrogate');
                const existing = live.edges.find((x) => x.from === e.from && x.to === e.to);
                if (existing && !e.data && e.label.trim() === existing.label.trim()) {
                    // host-bridge: the same wording from the writer who wrote it, or from one already
                    // listed, is nothing; from anyone else it is a second, independent source for the
                    // link, staged as one corroboration row that commit grades `recorded`.
                    const listed = existing.data?.corroborated_by ?? [];
                    if (writer === existing.data?.label_source || listed.includes(writer)) return;
                    staged.edgeUpdates.push({ edge: existing, label: undefined, data: { corroborated_by: [...listed, writer].sort() } });
                    return;
                }
                if (existing) {
                    staged.edgeUpdates.push({ edge: existing, label: e.label.trim() === existing.label.trim() ? undefined : e.label, data: e.data });
                    return;
                }
                // The backend holds one edge per ordered pair; a second create in one change set fails.
                if (staged.edges.some((x) => x.from === e.from && x.to === e.to)) {
                    throw new Error(`second edge for the pair ${e.from} -> ${e.to} in one run`);
                }
                staged.edges.push({ from: e.from, to: e.to, label: e.label, data: e.data });
            },
            // host-bridge's updateEdge: by id, a label equal to the live one is no relabel, and a call
            // with neither a new label nor data stages nothing.
            async updateEdge(id, patch) {
                const edge = live.edges.find((x) => x.id === id);
                if (!edge) throw new Error(`no edge ${id} in this project`);
                for (const r of ['confidence', 'confidence_source', 'label_source', 'corroborated_by']) {
                    if (patch?.data && r in patch.data) throw new Error(`updateEdge: ${r} is set by the host`);
                }
                if (unstorable(patch?.data) || unstorable(patch?.label)) throw new Error('updateEdge: a NUL character or an unpaired surrogate');
                const label = patch?.label !== undefined && patch.label.trim() !== edge.label.trim() ? patch.label : undefined;
                if (label === undefined && !patch?.data) return;
                staged.edgeUpdates.push({ edge, label, data: patch.data });
            },
        };
        const apply = () => {
            const real = new Map();
            for (const n of staged.creates) {
                const id = `n${++seq}`;
                real.set(n.id, id);
                live.nodes.set(id, { id, type: n.type, data: { ...n.data } });
            }
            for (const u of staged.updates) Object.assign(live.nodes.get(u.id).data, merge(live.nodes.get(u.id).data, u.data));
            for (const e of staged.edges) {
                const data = { ...(e.data ?? {}), label_source: writer };
                live.edges.push({ ...e, data, id: `e${++seq}`, from: real.get(e.from) ?? e.from, to: real.get(e.to) ?? e.to });
            }
            for (const u of staged.edgeUpdates) {
                if (u.label) u.edge.label = u.label;
                u.edge.data = { ...(u.edge.data ?? {}), ...(u.data ?? {}) };
            }
        };
        return { graph, staged, apply };
    }
    return { live, newRun };
}

const pack = (await import(pathToFileURL(join(here, 'dist', 'pack.mjs')).href)).default;
const plugin = pack.plugins[0];

const WRITER = `plugin:${plugin.manifest.identifier}`;

async function runOn(host, files, params = {}, { signal } = {}) {
    const run = host.newRun(WRITER);
    const ctx = {
        run: { runId: 'test', projectId: 'test', pluginId: plugin.manifest.identifier, grantedScopes: plugin.manifest.scopes, platform: 'web' },
        input: { selection: [] },
        params: { exports: files, ...params },
        config: {},
        graph: run.graph,
        progress: { set() {}, log() {}, status() {} },
        signal: signal ?? new AbortController().signal,
    };
    const result = await plugin.run(ctx);
    return { run, result };
}
const asFile = (name, bytes) => new File([bytes], name);
const fx = (name) => asFile(name, fixture(name));

/** The staged graph as sorted lines, so two runs can be compared whatever the order. */
function picture(run, { host = true } = {}) {
    const byId = new Map(run.staged.creates.map((n) => [n.id, n]));
    const label = (id) => {
        const n = byId.get(id);
        if (!n) return id;
        const d = n.data;
        const name =
            n.type === 'endpoint.process'
                ? `${d.process_name}#${d.pid}`
                : n.type === 'endpoint.file'
                ? `${d.file_name}@${host ? d.hostname ?? '' : ''}`
                : d.ip_address ?? d.domain_name;
        return `${n.type.split('.')[1]}:${name}`;
    };
    const nodes = run.staged.creates.map((n) => {
        const { hostname, ...rest } = n.data;
        return `${label(n.id)} ${JSON.stringify(host ? n.data : rest)}`;
    });
    const edges = run.staged.edges.map((e) => `${label(e.from)} -[${e.label}]-> ${label(e.to)} ${JSON.stringify(e.data ?? {})}`);
    return [...nodes.sort(), ...edges.sort()];
}
const nodesOf = (run, type) => run.staged.creates.filter((n) => n.type === type);
const edgeOf = (run, label, toValue, host) =>
    run.staged.edges.find((e) => {
        const to = run.staged.creates.find((n) => n.id === e.to) ?? host?.live.nodes.get(e.to);
        return e.label === label && to && (to.data.ip_address === toValue || to.data.domain_name === toValue || to.data.process_name === toValue || to.data.file_name === toValue);
    });

const SYSMON = [
    'sysmon-wevtutil.xml',
    'sysmon-evtxecmd.csv',
    'sysmon-winlogbeat.ndjson',
    'sysmon-velociraptor.json',
    'sysmon-evtx_dump.txt',
    'sysmon-getwinevent.json',
    'sysmon-eventviewer.csv',
    'sysmon-splunk.csv',
];
const PS = '{4f3a1c2e-2d13-6729-5102-000000001c00}';

await test('a Sysmon export becomes processes linked to where they went, what spawned them and what they ran', async () => {
    const { run, result } = await runOn(makeHost(), [fx('sysmon-wevtutil.xml')]);
    const procs = nodesOf(run, 'endpoint.process');
    assert.deepEqual(procs.map((n) => n.data.process_name).sort(), ['WINWORD.EXE', 'explorer.exe', 'powershell.exe', 'svchost.exe']);
    const ps = procs.find((n) => n.data.process_guid === PS);
    assert.equal(ps.data.pid, 6644);
    assert.equal(ps.data.parent_pid, 4120);
    assert.equal(ps.data.user, 'ACME\\jkim');
    assert.equal(ps.data.start_time, '2026-11-04T01:11:47.902Z');
    assert.equal(ps.data.hostname, 'WKS-FIN-0142.acme.example');
    assert.equal(ps.data.image_path, 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe');
    assert.match(ps.data.command_line, /^powershell\.exe -nop -w hidden -enc /);
    const explorer = procs.find((n) => n.data.process_name === 'explorer.exe');
    assert.equal(explorer.data.pid, 3880, 'a parent known only from its child still carries its PID');

    const files = nodesOf(run, 'endpoint.file');
    assert.deepEqual(files.map((n) => n.data.file_name).sort(), ['WINWORD.EXE', 'powershell.exe']);
    const psFile = files.find((n) => n.data.file_name === 'powershell.exe');
    assert.match(psFile.data.sha256, /^[0-9a-f]{64}$/, 'lower case hex');
    assert.match(psFile.data.md5, /^[0-9a-f]{32}$/);
    assert.equal(psFile.data.original_file_name, 'PowerShell.EXE');
    assert.equal(psFile.data.hostname, 'WKS-FIN-0142.acme.example');
    assert.equal(psFile.data.file_path, ps.data.image_path);

    assert.deepEqual(nodesOf(run, 'infrastructure.ip_address').map((n) => n.data.ip_address).sort(), ['198.51.100.23', '2001:db8::ff00:42:8329', '203.0.113.45']);
    assert.deepEqual(nodesOf(run, 'infrastructure.domain').map((n) => n.data.domain_name), ['update-check.example.net']);

    const c2 = edgeOf(run, 'connected to', '203.0.113.45');
    assert.deepEqual(c2.data, {
        source: 'sysmon',
        events: 3,
        direction: 'outbound',
        first_seen: '2026-11-04T01:12:09.441Z',
        last_seen: '2026-11-04T01:22:09.460Z',
        ports: [443, 8443],
        protocols: ['tcp'],
        remote_hostnames: ['edge-1.example.org'],
    });
    const rdp = edgeOf(run, 'accepted connection from', '198.51.100.23');
    assert.ok(rdp, 'an accepted connection points from the process to the peer that opened it');
    assert.deepEqual(rdp.data.ports, [3389]);
    assert.equal(rdp.data.direction, 'inbound');
    const q = edgeOf(run, 'queried', 'update-check.example.net');
    assert.equal(q.data.events, 2);
    assert.deepEqual(q.data.answers, ['edge-1.example.org', '203.0.113.45']);
    assert.ok(edgeOf(run, 'spawned', 'powershell.exe'));
    assert.ok(edgeOf(run, 'spawned', 'WINWORD.EXE'), 'the chain reaches past the immediate parent');
    assert.ok(edgeOf(run, 'executed from', 'powershell.exe'));
    assert.equal(run.staged.edges.length, 8);

    assert.equal(result.counts.processes, 4);
    assert.equal(result.counts.private_skipped, 1);
    assert.equal(result.counts.local_skipped, 1);
    assert.equal(result.counts.no_guid, 1);
    assert.match(result.summary, /1 connection to private-network addresses/);
    assert.match(result.summary, /1 query for internal names/);
    assert.match(result.summary, /1 reverse lookup/);
    assert.match(result.summary, /1 event with no ProcessGuid/);
    assert.match(result.summary, /sysmon-wevtutil\.xml \(event XML, 13 Sysmon events\)/, 'fifteen records: one without a GUID, one process-terminated');
});

const reference = picture((await runOn(makeHost(), [fx('sysmon-wevtutil.xml')])).run);
for (const name of SYSMON.slice(1)) {
    await test(`${name} yields the same graph as the XML export`, async () => {
        const { run } = await runOn(makeHost(), [fx(name)]);
        // Event Viewer's CSV does not name the computer, so the host is the one thing it cannot give.
        const host = name !== 'sysmon-eventviewer.csv';
        const want = host ? reference : picture((await runOn(makeHost(), [fx('sysmon-wevtutil.xml')])).run, { host: false });
        assert.deepEqual(picture(run, { host }), want);
    });
}

await test('a UTF-16 file (PowerShell 5.1 Out-File) reads the same, with or without its BOM', async () => {
    for (const name of ['sysmon-getwinevent.json', 'sysmon-wevtutil.xml', 'sysmon-evtxecmd.csv']) {
        const le = Buffer.from(fixture(name).toString('utf8'), 'utf16le');
        const withBom = (await runOn(makeHost(), [asFile(name, Buffer.concat([Buffer.from([0xff, 0xfe]), le]))])).run;
        const bare = (await runOn(makeHost(), [asFile(name, le)])).run;
        assert.deepEqual(picture(withBom), reference, `${name} with BOM`);
        assert.deepEqual(picture(bare), reference, `${name} without BOM`);
    }
});

await test('the same process in several exports of one run is one node, and its links are summed', async () => {
    const { run } = await runOn(makeHost(), [fx('sysmon-wevtutil.xml'), fx('sysmon-splunk.csv')]);
    assert.equal(nodesOf(run, 'endpoint.process').filter((n) => n.data.process_guid === PS).length, 1);
    assert.equal(edgeOf(run, 'connected to', '203.0.113.45').data.events, 6);
});

await test('private destinations come in only when asked; a single-label name never does', async () => {
    const { run, result } = await runOn(makeHost(), [fx('sysmon-wevtutil.xml')], { include_private: true });
    assert.ok(edgeOf(run, 'connected to', '10.20.0.5'), 'the SMB connection to 10.20.0.5');
    assert.ok(!nodesOf(run, 'infrastructure.domain').some((n) => n.data.domain_name === 'wpad'));
    assert.match(result.summary, /1 name the Domain type does not accept/);
    assert.ok(!nodesOf(run, 'infrastructure.ip_address').some((n) => n.data.ip_address === '127.0.0.1'), 'loopback never');
});

await test('processes with no activity come in only when asked', async () => {
    const head = 'EventCode,ProcessGuid,ProcessId,Image,UtcTime,Hashes,host\r\n';
    const notepad = `1,{11111111-2222-3333-4444-555555555555},900,C:\\Windows\\notepad.exe,2026-11-04 02:00:00.000,SHA256=${'e'.repeat(64)},H1\r\n`;
    const off = await runOn(makeHost(), [asFile('n.csv', Buffer.from(head + notepad))]);
    assert.equal(nodesOf(off.run, 'endpoint.process').length, 0);
    const on = await runOn(makeHost(), [asFile('n.csv', Buffer.from(head + notepad))], { include_inactive: true });
    assert.equal(nodesOf(on.run, 'endpoint.process').length, 1);
    assert.equal(nodesOf(on.run, 'endpoint.file').length, 1);
});

await test("Sysmon's all-zero parent GUID is no parent, so orphans do not share one", async () => {
    const zero = '{00000000-0000-0000-0000-000000000000}';
    const rows = [
        'EventCode,ProcessGuid,ProcessId,Image,ParentProcessGuid,ParentProcessId,ParentImage,DestinationIp,DestinationPort,host',
        `1,{4f3a1c2e-0001-6729-0000-000000000001},404,C:\\Windows\\System32\\smss.exe,${zero},4,System,,,H1`,
        `1,{4f3a1c2e-0002-6729-0000-000000000002},512,C:\\Windows\\System32\\csrss.exe,${zero},4,System,,,H1`,
    ].join('\r\n');
    const { run } = await runOn(makeHost(), [asFile('boot.csv', Buffer.from(rows))], { include_inactive: true });
    const procs = nodesOf(run, 'endpoint.process');
    assert.deepEqual(procs.map((n) => n.data.process_name).sort(), ['csrss.exe', 'smss.exe']);
    assert.equal(run.staged.edges.filter((e) => e.label === 'spawned').length, 0);
});

await test('ECS (Elastic Defend): entity_id kept as given, parents, hashes, DNS answers as edge data', async () => {
    const { run } = await runOn(makeHost(), [fx('ecs-defend.ndjson')]);
    const procs = nodesOf(run, 'endpoint.process');
    assert.deepEqual(procs.map((n) => n.data.process_name).sort(), ['bash', 'curl', 'sshd']);
    const curl = procs.find((n) => n.data.process_name === 'curl');
    assert.equal(curl.data.process_guid, 'NzY0NTMyNzEtMWQ3Ni00MmM0LWE4ZDEtYjI2ZWQ0ZGE1NmQzLTQ0NzgtMTczMDY4MzY1MA==');
    assert.equal(curl.data.user, 'deploy');
    assert.equal(curl.data.hostname, 'build-07');
    assert.deepEqual(nodesOf(run, 'endpoint.file').map((n) => n.data.file_path).sort(), ['/usr/bin/bash', '/usr/bin/curl']);
    assert.deepEqual(edgeOf(run, 'queried', 'cdn.example.com').data.answers, ['198.51.100.77', '2001:db8::1:0:0:77']);
    assert.equal(edgeOf(run, 'connected to', '198.51.100.77').data.source, 'ecs');
    assert.deepEqual(edgeOf(run, 'accepted connection from', '203.0.113.200').data.ports, [22]);
    assert.ok(edgeOf(run, 'spawned', 'curl') && edgeOf(run, 'spawned', 'bash'));
});

await test("Kibana's CSV: dotted columns; a formatted local date is left out rather than guessed", async () => {
    const { run } = await runOn(makeHost(), [fx('ecs-defend.ndjson'), fx('ecs-kibana.csv')]);
    const first = edgeOf(run, 'connected to', '198.51.100.77');
    assert.equal(first.data.events, 2);
    assert.equal(first.data.first_seen, '2026-11-04T03:20:40.700Z', 'from the Defend record only');
    assert.equal(edgeOf(run, 'connected to', '198.51.100.78').data.first_seen, '2026-11-04T03:25:02.000Z');
    assert.equal(nodesOf(run, 'endpoint.process').filter((n) => n.data.process_name === 'curl').length, 1);
});

await test("Elastic Defend's own spelling: incoming/outgoing, a disconnect per connection, a lookup logged twice", async () => {
    const { run, result } = await runOn(makeHost(), [fx('ecs-defend-endpoint.ndjson')], { include_private: true });
    assert.equal(result.counts.refused, 0, result.summary);
    assert.deepEqual(
        nodesOf(run, 'infrastructure.ip_address').map((n) => n.data.ip_address).sort(),
        ['192.0.2.80', '203.0.113.200', '203.0.113.201', '203.0.113.202'],
        "never the host's own address",
    );
    const bare = edgeOf(run, 'accepted connection from', '203.0.113.202');
    assert.deepEqual([bare.data.direction, bare.data.events], ['inbound', 1], 'no host.ip to go by: `incoming` alone decides');
    const ssh = edgeOf(run, 'accepted connection from', '203.0.113.200');
    assert.equal(ssh.data.direction, 'inbound', '`incoming` is inbound');
    assert.equal(ssh.data.events, 1, 'its disconnect is the same connection');
    assert.deepEqual(ssh.data.ports, [22]);
    assert.equal(ssh.data.last_seen, '2026-11-04T04:09:00.000Z', 'the disconnect still dates the pair');
    const flow = edgeOf(run, 'accepted connection from', '203.0.113.201');
    assert.equal(flow?.data.direction, 'inbound', "no direction given: the destination is one of host.ip");
    const out = edgeOf(run, 'connected to', '192.0.2.80');
    assert.equal(out.data.direction, 'outbound');
    assert.equal(out.data.events, 1);
    const q = edgeOf(run, 'queried', 'dl.example.org');
    assert.equal(q.data.events, 1, 'lookup_requested and lookup_result are one lookup');
    assert.deepEqual(q.data.answers, ['192.0.2.80']);
    assert.ok(edgeOf(run, 'spawned', 'curl'));
});

await test('every write passes the type packs, and no pair is linked twice in one run', async () => {
    // makeHost throws on both; reaching here with nothing refused is the assertion.
    const { result } = await runOn(makeHost(), SYSMON.map(fx).concat([fx('ecs-defend.ndjson'), fx('ecs-defend-endpoint.ndjson'), fx('ecs-kibana.csv')]), {
        include_private: true,
        include_inactive: true,
    });
    assert.equal(result.counts.refused, 0, result.summary);
});

await test('a second import onto the applied graph adds no node and re-asserts no plain link', async () => {
    const host = makeHost();
    const first = await runOn(host, [fx('sysmon-wevtutil.xml')]);
    first.run.apply();
    const again = await runOn(host, [fx('sysmon-wevtutil.xml')]);
    assert.equal(again.run.staged.creates.length, 0, 'every node is found by its identity');
    assert.equal(again.run.staged.edges.length, 0);
    // Links that carry a summary are restated with it; spawned / executed from carry none and are silent.
    // The four restatements change nothing here, and the host stages them anyway: it cannot tell, and
    // neither can the pack, which reads edges without their data. The pack page says so.
    assert.ok(again.run.staged.edgeUpdates.every((u) => u.data && u.label === undefined), 'never a relabel');
    assert.ok(again.run.staged.edgeUpdates.every((u) => !('corroborated_by' in u.data)), 'never its own corroborator');
    assert.equal(again.run.staged.edgeUpdates.length, 4);
});

await test('a link already in the project keeps its label, whoever wrote it', async () => {
    const host = makeHost();
    (await runOn(host, [fx('sysmon-wevtutil.xml')])).run.apply();
    const c2 = host.live.edges.find((e) => e.label === 'connected to' && host.live.nodes.get(e.to).data.ip_address === '203.0.113.45');
    // What the Properties panel does on a rename: the new wording, and the analyst as its source.
    const rename = (e, label) => Object.assign(e, { label, data: { ...e.data, label_source: 'analyst' } });
    rename(c2, 'C2 beacon');
    const spawn = rename(host.live.edges.find((e) => e.label === 'spawned'), 'injected into');
    const exec = rename(host.live.edges.find((e) => e.label === 'executed from'), 'loaded from');
    const { run, result } = await runOn(host, [fx('sysmon-splunk.csv')]);
    assert.ok(run.staged.edgeUpdates.every((u) => u.label === undefined), 'no relabel proposed');
    assert.equal(run.staged.edgeUpdates.find((u) => u.edge === c2).data.events, 3, 'the summary still updates');
    // Restating the analyst's wording would make the pack a second, independent source for a
    // sentence it never wrote: the host records that as corroboration and grades the link on it.
    assert.ok(!run.staged.edgeUpdates.some((u) => u.edge === spawn || u.edge === exec), 'a renamed plain link is left alone');
    assert.ok(run.staged.edgeUpdates.every((u) => !('corroborated_by' in (u.data ?? {}))), 'no corroboration staged');
    assert.equal(result.counts.labels_kept, 3);
    assert.match(result.summary, /3 links already in the project kept their label/);
});

await test("a link another writer drew in the pack's own wording is corroborated once, never relabelled", async () => {
    const host = makeHost();
    (await runOn(host, [fx('sysmon-wevtutil.xml')])).run.apply();
    // The same `spawned`, drawn first by someone else: the export saying so too is a second source.
    const spawn = host.live.edges.find((e) => e.label === 'spawned');
    spawn.data = { ...spawn.data, label_source: 'agent' };
    const second = await runOn(host, [fx('sysmon-wevtutil.xml')]);
    const rows = second.run.staged.edgeUpdates.filter((u) => u.edge === spawn);
    assert.deepEqual(rows.map((u) => [u.label, u.data]), [[undefined, { corroborated_by: [WRITER] }]]);
    second.run.apply();
    const third = await runOn(host, [fx('sysmon-wevtutil.xml')]);
    assert.ok(!third.run.staged.edgeUpdates.some((u) => u.edge === spawn), 'once');
});

await test("a pair first seen inbound keeps its label when an outbound connection follows; direction says both", async () => {
    const head = 'EventCode,UtcTime,ProcessGuid,ProcessId,Image,SourceIp,SourcePort,DestinationIp,DestinationPort,Initiated,host\r\n';
    const g = '{bbbbbbbb-0000-4000-8000-000000000001}';
    const inbound = `3,2026-11-04 01:00:00.000,${g},50,C:\\s.exe,203.0.113.7,51000,10.0.0.5,3389,false,H1\r\n`;
    const outbound = `3,2026-11-04 02:00:00.000,${g},50,C:\\s.exe,10.0.0.5,52000,203.0.113.7,443,true,H1\r\n`;
    const host = makeHost();
    (await runOn(host, [asFile('in.csv', Buffer.from(head + inbound))])).run.apply();
    assert.equal(host.live.edges[0].label, 'accepted connection from');
    const second = await runOn(host, [asFile('both.csv', Buffer.from(head + inbound + outbound))]);
    second.run.apply();
    assert.equal(host.live.edges[0].label, 'accepted connection from');
    assert.equal(host.live.edges[0].data.direction, 'both');
});

await test("a re-import replaces a link's summary whole: keys it has no value for are cleared", async () => {
    const head = 'EventCode,UtcTime,ProcessGuid,ProcessId,Image,QueryName,QueryStatus,QueryResults,host\r\n';
    const g = '{cccccccc-0000-4000-8000-000000000001}';
    const failing = `22,2026-11-04 01:00:00.000,${g},60,C:\\q.exe,later.example.com,9003,-,H1\r\n`;
    const resolving = `22,2026-11-05 01:00:00.000,${g},60,C:\\q.exe,later.example.com,0,::ffff:198.51.100.9;,H1\r\n`;
    const host = makeHost();
    const first = await runOn(host, [asFile('a.csv', Buffer.from(head + failing))]);
    assert.equal(first.run.staged.edges[0].data.failed_events, 1);
    assert.ok(!('answers' in first.run.staged.edges[0].data), 'a new link carries no empty keys');
    first.run.apply();
    (await runOn(host, [asFile('b.csv', Buffer.from(head + resolving))])).run.apply();
    const d = host.live.edges[0].data;
    assert.equal(d.events, 1);
    assert.equal(d.failed_events, null);
    assert.equal(d.statuses, null);
    assert.deepEqual(d.answers, ['198.51.100.9']);
    assert.equal(d.first_seen, '2026-11-05T01:00:00.000Z');
});

await test('every data key a link carries is one its kind declares, so a re-import can clear it', async () => {
    const { run } = await runOn(makeHost(), SYSMON.map(fx).concat([fx('ecs-defend.ndjson'), fx('ecs-defend-endpoint.ndjson')]), { include_private: true });
    const kinds = { 'connected to': P.CONN_KEYS, 'accepted connection from': P.CONN_KEYS, queried: P.LOOKUP_KEYS };
    for (const e of run.staged.edges) {
        if (!e.data) continue;
        for (const k of Object.keys(e.data)) assert.ok(kinds[e.label].includes(k), `${e.label}: ${k}`);
    }
});

await test('NUL and unpaired surrogates in a command line become U+FFFD instead of a row the server refuses', async () => {
    const ev = {
        EventID: 1,
        Computer: 'H1',
        EventData: {
            UtcTime: '2026-11-04 01:00:00.000',
            ProcessGuid: '{dddddddd-0000-4000-8000-000000000001}',
            ProcessId: '70',
            Image: 'C:\\Users\\Public\\\ud800x.exe',
            CommandLine: 'x.exe --a \u0000 --b \udc00 --ok 😀',
            Hashes: `SHA256=${'f'.repeat(64)}`,
        },
    };
    const dns = { EventID: 22, Computer: 'H1', EventData: { ProcessGuid: ev.EventData.ProcessGuid, ProcessId: '70', Image: ev.EventData.Image, QueryName: 'c2.example.com', QueryResults: '::ffff:203.0.113.8;' } };
    const lines = [ev, dns].map((x) => JSON.stringify(x)).join('\n');
    assert.match(lines, /\\u0000/, 'the export carries the escapes as JSON does');
    const { run, result } = await runOn(makeHost(), [asFile('odd.jsonl', Buffer.from(lines))]);
    assert.equal(result.counts.refused, 0, result.summary);
    const proc = nodesOf(run, 'endpoint.process')[0];
    assert.equal(proc.data.command_line, 'x.exe --a \ufffd --b \ufffd --ok 😀', 'a valid pair is kept');
    assert.equal(proc.data.process_name, '\ufffdx.exe');
    assert.equal(P.storable('a\u0000b\ud83d\ude00c\ud83d'), 'a\ufffdb\ud83d\ude00c\ufffd');
});

await test('known infrastructure is counted and its process goes first when the run is capped', async () => {
    const host = makeHost();
    const seed = host.newRun();
    await seed.graph.createNode({ type: 'infrastructure.ip_address', data: { ip_address: '203.0.113.45' } });
    seed.apply();
    const { result } = await runOn(host, [fx('sysmon-wevtutil.xml')]);
    assert.equal(result.counts.known, 1);
    assert.match(result.summary, /1 destination was already in this project/);
});

/** N processes, each reaching its own address: N×2 nodes, N links. */
function manyProcesses(count, { cmdBytes = 0, known = null, char = 'A' } = {}) {
    const rows = ['EventCode,UtcTime,ProcessGuid,ProcessId,Image,CommandLine,DestinationIp,DestinationPort,Initiated,host'];
    for (let i = 0; i < count; i++) {
        const g = `{${String(i).padStart(8, '0')}-0000-4000-8000-000000000001}`;
        const ip = i === count - 1 && known ? known : `198.18.${(i >> 8) & 255}.${i & 255}`;
        const t = new Date(Date.UTC(2026, 10, 4, 0, 0, 0) + i * 1000).toISOString().replace('T', ' ').replace('Z', '');
        rows.push(`3,${t},${g},${1000 + i},C:\\Tools\\t${i}.exe,"${char.repeat(cmdBytes)}",${ip},443,true,H1`);
    }
    return asFile('many.csv', Buffer.from(rows.join('\r\n')));
}

await test('a run stops at 1,500 nodes, says so, and keeps the process that reached known infrastructure', async () => {
    const host = makeHost();
    const seed = host.newRun();
    await seed.graph.createNode({ type: 'infrastructure.ip_address', data: { ip_address: '203.0.113.99' } });
    seed.apply();
    const { run, result } = await runOn(host, [manyProcesses(1000, { known: '203.0.113.99' })]);
    assert.ok(run.staged.creates.length <= 1500, `${run.staged.creates.length} nodes`);
    assert.equal(result.counts.processes, 750);
    assert.equal(result.counts.not_imported, 250);
    assert.match(result.summary, /250 more processes not imported: a run stops at 1,500 nodes/);
    assert.ok(edgeOf(run, 'connected to', '203.0.113.99', host), 'the last process in time order, first in rank');
});

/**
 * The run's change set as the batch-changes request commit.ts sends for it, measured as the backend
 * measures it. Row framing as commit writes it: a temp_id (a UUID) and type_pack per node; UUID
 * endpoints and the three provenance keys commit stamps per edge, beside the pack's own data.
 */
function requestBytes(run) {
    const uuid = '00000000-0000-4000-8000-000000000000';
    const body = {
        creates: {
            nodes: run.staged.creates.map((n) => ({ temp_id: uuid, type: n.type, type_pack: 'run.vineyard.typepacks.infrastructure@10.10.10', data: n.data })),
            edges: run.staged.edges.map((e) => ({
                from: uuid,
                to: uuid,
                label: e.label,
                data: { ...(e.data ?? {}), label_source: WRITER, confidence: 'unassessed', confidence_source: WRITER },
            })),
        },
        updates: { nodes: [], edges: [] },
        deletes: { nodes: [], edges: [] },
    };
    return pyBytes(body);
}

await test('a run also stops before 3 MB of changes, which long command lines reach first', async () => {
    const { run, result } = await runOn(makeHost(), [manyProcesses(80, { cmdBytes: 60_000 })]);
    assert.match(result.summary, /a run stops at 3 MB of changes/);
    const bytes = requestBytes(run);
    assert.ok(bytes < 3.2 * 1024 * 1024, `${bytes} bytes in the request`);
    assert.ok(result.counts.processes >= 45, `${result.counts.processes} processes: the budget is used, not wasted`);
});

await test('the 3 MB is counted as the server counts it, so non-ASCII command lines still fit one request', async () => {
    // The backend measures json.dumps output with ensure_ascii: a Hangul syllable or an accented
    // letter is six bytes there (three and two in UTF-8), an emoji twelve (four in UTF-8).
    for (const [char, length, least] of [
        ['가', 20_000, 20],
        ['é', 30_000, 13],
        ['😀', 10_000, 20],
    ]) {
        const { run, result } = await runOn(makeHost(), [manyProcesses(80, { cmdBytes: length, char })]);
        assert.equal(result.counts.refused, 0, result.summary);
        assert.match(result.summary, /a run stops at 3 MB of changes/, char);
        const bytes = requestBytes(run);
        assert.ok(bytes < BULK_MAX_BYTES, `${char}: ${bytes} bytes in the request, over ${BULK_MAX_BYTES}`);
        assert.ok(bytes < 3.2 * 1024 * 1024, `${char}: ${bytes} bytes, past the 3 MB budget`);
        assert.ok(result.counts.processes >= least, `${char}: ${result.counts.processes} processes: the budget is used, not wasted`);
    }
});

await test("a command line past the server's row limit is cut to fit and says so; a Windows-length one is not", async () => {
    // Linux allows about 2 MB of arguments (128 KB each), and an ECS export carries the command line
    // whole. The backend refuses a node whose data is over 256 KiB as it measures it, at apply time.
    const proc = (n, cmd) => ({ entity_id: `bnVsbC0${n}`, pid: 3000 + n, name: `job${n}`, executable: `/opt/job${n}`, command_line: cmd });
    const host = { name: 'ci-02' };
    const cmds = {
        ascii: 'xargs-built ' + 'a'.repeat(300_000),
        // Six ASCII characters apart, the two cuts land one UTF-16 unit apart, so one of them falls
        // between the halves of a pair.
        emoji: '😀'.repeat(40_001),
        emoji6: 'abcdef' + '😀'.repeat(40_001),
        windows: '가'.repeat(32_767), // Windows' own maximum, all non-ASCII: never cut
    };
    const lines = Object.values(cmds).flatMap((cmd, n) => [
        { '@timestamp': `2026-11-04T05:0${n}:00.000Z`, event: { category: ['process'], type: ['start'], action: 'exec' }, process: proc(n, cmd), host },
        {
            '@timestamp': `2026-11-04T05:0${n}:01.000Z`,
            event: { category: ['network'], type: ['start'], action: 'connection_attempted' },
            destination: { ip: `192.0.2.${10 + n}`, port: 443 },
            network: { direction: 'outgoing' },
            process: proc(n, cmd),
            host,
        },
    ]);
    const file = asFile('long.ndjson', Buffer.from(lines.map((x) => JSON.stringify(x)).join('\n')));
    const { run, result } = await runOn(makeHost(), [file]);
    assert.equal(result.counts.refused, 0, result.summary);
    const byName = Object.fromEntries(nodesOf(run, 'endpoint.process').map((n) => [n.data.process_name, n.data]));
    for (const [n, key] of [[0, 'ascii'], [1, 'emoji'], [2, 'emoji6']]) {
        const d = byName[`job${n}`];
        assert.ok(pyBytes(d) <= GRAPH_DATA_MAX_BYTES, `${key}: ${pyBytes(d)} bytes`);
        assert.equal(d.command_line_truncated, true, key);
        assert.equal(d.command_line_length, cmds[key].length, key);
        assert.ok(cmds[key].startsWith(d.command_line) && d.command_line.length > 20_000, `${key}: the start is kept`);
        assert.ok(!unstorable(d.command_line), `${key}: no half of a pair left at the cut`);
    }
    assert.equal(byName.job3.command_line, cmds.windows);
    assert.ok(!('command_line_truncated' in byName.job3));
});

await test('a process reaching hundreds of destinations keeps the 200 with the most events', async () => {
    const rows = ['EventCode,ProcessGuid,ProcessId,Image,DestinationIp,DestinationPort,host'];
    for (let i = 0; i < 250; i++) rows.push(`3,{aaaaaaaa-0000-4000-8000-000000000001},77,C:\\b.exe,198.18.1.${i},443,H1`);
    rows.push('3,{aaaaaaaa-0000-4000-8000-000000000001},77,C:\\b.exe,198.18.1.7,80,H1'); // a second event for .7
    const { run, result } = await runOn(makeHost(), [asFile('b.csv', Buffer.from(rows.join('\n')))]);
    assert.equal(nodesOf(run, 'infrastructure.ip_address').length, 200);
    assert.ok(edgeOf(run, 'connected to', '198.18.1.7'), 'the busiest is kept');
    assert.equal(nodesOf(run, 'endpoint.process')[0].data.destinations_not_imported, 50);
    assert.match(result.summary, /reached more than 200 destinations/);
});

await test('destinations_not_imported lands on the process even when a child placed it first', async () => {
    const head = 'EventCode,UtcTime,ProcessGuid,ProcessId,Image,ParentProcessGuid,ParentProcessId,ParentImage,DestinationIp,DestinationPort,Initiated,host';
    const parent = '{eeeeeeee-0000-4000-8000-000000000001}';
    const child = '{eeeeeeee-0000-4000-8000-000000000002}';
    // The child is active first, so its unit goes first and draws the parent as its ancestor.
    const rows = [
        head,
        `1,2026-11-04 01:00:00.000,${child},20,C:\\c.exe,${parent},10,C:\\p.exe,,,,H1`,
        `3,2026-11-04 01:00:01.000,${child},20,C:\\c.exe,,,,203.0.113.9,443,true,H1`,
    ];
    for (let i = 0; i < 230; i++) rows.push(`3,2026-11-04 02:00:00.000,${parent},10,C:\\p.exe,,,,198.18.${2 + (i >> 8)}.${i & 255},443,true,H1`);
    const { run, result } = await runOn(makeHost(), [asFile('fan.csv', Buffer.from(rows.join('\r\n')))]);
    const procs = nodesOf(run, 'endpoint.process');
    assert.equal(procs.length, 2);
    assert.equal(procs.find((n) => n.data.process_guid === parent).data.destinations_not_imported, 30);
    assert.ok(!('destinations_not_imported' in procs.find((n) => n.data.process_guid === child).data));
    assert.match(result.summary, /1 process reached more than 200 destinations/);
});

await test('without the Endpoint type pack it says what to install and stages nothing', async () => {
    const types = Object.fromEntries(Object.entries(ALL_TYPES).filter(([k]) => !k.startsWith('endpoint.')));
    const { run, result } = await runOn(makeHost({ types }), [fx('sysmon-wevtutil.xml')]);
    assert.match(result.summary, /Endpoint type pack is not installed/);
    assert.equal(run.staged.creates.length + run.staged.edges.length, 0);
});

await test('without the Infrastructure type pack the processes still come in', async () => {
    const types = Object.fromEntries(Object.entries(ALL_TYPES).filter(([k]) => k.startsWith('endpoint.')));
    const { run, result } = await runOn(makeHost({ types }), [fx('sysmon-wevtutil.xml')]);
    assert.equal(nodesOf(run, 'endpoint.process').length, 4);
    assert.match(result.summary, /Infrastructure type pack is not installed/);
});

await test('nothing to read, no files, and a stopped run all return rather than throw', async () => {
    const security = asFile('security.csv', Buffer.from('EventID,SubjectUserName,TargetUserName\r\n4624,-,jkim\r\n'));
    const none = await runOn(makeHost(), [security, asFile('empty.json', Buffer.from(''))]);
    assert.match(none.result.summary, /^No Sysmon \(events 1, 3, 22\) or ECS process, network or DNS events found in 2 files/);
    const empty = await runOn(makeHost(), []);
    assert.match(empty.result.summary, /^No exports provided/);
    const ac = new AbortController();
    ac.abort();
    const stopped = await runOn(makeHost(), [fx('sysmon-wevtutil.xml')], {}, { signal: ac.signal });
    assert.equal(stopped.run.staged.creates.length, 0);
});

await test('the same input always plans the same writes in the same order', async () => {
    const a = (await runOn(makeHost(), SYSMON.map(fx))).run;
    const b = (await runOn(makeHost(), SYSMON.map(fx))).run;
    assert.deepEqual(a.staged.creates, b.staged.creates);
    assert.deepEqual(a.staged.edges, b.staged.edges);
});

await test('plugins/host-artifacts.manifest.json is what gen-manifest.mjs makes from this bundle', () => {
    const manifest = JSON.parse(readFileSync(join(here, 'plugins', 'host-artifacts.manifest.json'), 'utf8'));
    assert.equal(manifest.identifier, pack.identifier);
    assert.equal(manifest.version, pack.version);
    assert.equal(manifest.summary, pack.summary);
    assert.equal(manifest.description, pack.description);
    const { author, license, ...m } = plugin.manifest;
    assert.deepEqual(manifest.plugins[0], m);
    assert.deepEqual(Object.keys(manifest.plugins[0].params.properties), ['exports', 'include_private', 'include_inactive']);
    assert.deepEqual(manifest.plugins[0].scopes, { graph: ['node:read', 'node:create', 'edge:read', 'edge:create'] }, 'no network, no update');
    assert.ok(manifest.summary.length <= 250 && manifest.description.length <= 16000);
});

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
