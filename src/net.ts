// Addresses and names as a host log writes them, turned into the one spelling the graph keys on.
//
// `infrastructure.ip_address` and `infrastructure.domain` are identified by their value, compared
// byte for byte (the domain folds case, the address does not). Sysmon writes an IPv4 answer as
// `::ffff:203.0.113.10` and an IPv6 address in whatever form Windows rendered it, so writing the
// log's text straight through would put one address on the canvas twice: once from this pack and
// once from every DNS pack that wrote the dotted quad. Everything here is pure and dependency-free
// so the tests can call it without a sandbox.

export type AddressClass = 'public' | 'private' | 'local';

export interface Address {
    /** Canonical text: dotted quad, or RFC 5952 IPv6 (lower case, longest zero run compressed). */
    ip: string;
    version: 'ipv4' | 'ipv6';
    /**
     * `local` never leaves the machine or the link (loopback, link-local, multicast, unspecified,
     * the reserved 240/4 block) and is never imported. `private` is someone's internal network
     * (RFC 1918, CGNAT, unique-local) and is imported only when the analyst asks for it.
     */
    cls: AddressClass;
}

function parseV4(s: string): number[] | null {
    const parts = s.split('.');
    if (parts.length !== 4) return null;
    const out: number[] = [];
    for (const p of parts) {
        // Decimal only. `010` is octal to inet_aton and decimal to everyone else, and a log line that
        // spells an octet that way is not worth guessing about.
        if (!/^\d{1,3}$/.test(p) || (p.length > 1 && p[0] === '0')) return null;
        const n = Number(p);
        if (n > 255) return null;
        out.push(n);
    }
    return out;
}

function parseV6(input: string): number[] | null {
    let s = input;
    // A zone index (`fe80::1%12`) names an interface on the logging machine, not part of the address.
    const zone = s.indexOf('%');
    if (zone >= 0) s = s.slice(0, zone);
    if (!s || !/^[0-9a-fA-F:.]+$/.test(s)) return null;
    // An embedded IPv4 tail (`::ffff:203.0.113.10`) supplies the last two groups.
    let tail: number[] = [];
    if (s.includes('.')) {
        const at = s.lastIndexOf(':');
        if (at < 0) return null;
        const v4 = parseV4(s.slice(at + 1));
        if (!v4) return null;
        tail = [(v4[0] << 8) | v4[1], (v4[2] << 8) | v4[3]];
        s = s.slice(0, at + 1);
        // Keep a `::` that ends right before the tail; drop the single separator colon otherwise.
        if (!s.endsWith('::')) s = s.slice(0, -1);
    }
    const gap = s.indexOf('::');
    if (gap !== s.lastIndexOf('::')) return null;
    const want = 8 - tail.length;
    const split = (h: string) => (h === '' ? [] : h.split(':'));
    let groups: string[];
    if (gap >= 0) {
        const head = split(s.slice(0, gap));
        const rest = split(s.slice(gap + 2));
        const fill = want - head.length - rest.length;
        if (fill < 1) return null;
        groups = [...head, ...new Array<string>(fill).fill('0'), ...rest];
    } else {
        groups = split(s);
        if (groups.length !== want) return null;
    }
    const out: number[] = [];
    for (const g of groups) {
        if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
        out.push(parseInt(g, 16));
    }
    return [...out, ...tail];
}

/** RFC 5952 text for eight 16-bit groups. */
function formatV6(g: number[]): string {
    let bestAt = -1;
    let bestLen = 0;
    for (let i = 0; i < 8; ) {
        if (g[i] !== 0) {
            i++;
            continue;
        }
        let j = i;
        while (j < 8 && g[j] === 0) j++;
        // Only a run of two or more groups is compressed, and the first of equal runs wins.
        if (j - i > bestLen && j - i >= 2) {
            bestAt = i;
            bestLen = j - i;
        }
        i = j;
    }
    const hex = g.map((x) => x.toString(16));
    if (bestAt < 0) return hex.join(':');
    return `${hex.slice(0, bestAt).join(':')}::${hex.slice(bestAt + bestLen).join(':')}`;
}

function classifyV4(o: number[]): AddressClass {
    const [a, b] = o;
    if (a === 0 || a === 127 || (a === 169 && b === 254) || a >= 224) return 'local';
    if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)) return 'private';
    if (a === 100 && b >= 64 && b <= 127) return 'private'; // RFC 6598 carrier-grade NAT
    return 'public';
}

function classifyV6(g: number[]): AddressClass {
    if (g.every((x) => x === 0)) return 'local'; // ::
    if (g.slice(0, 7).every((x) => x === 0) && g[7] === 1) return 'local'; // ::1
    if ((g[0] & 0xffc0) === 0xfe80) return 'local'; // link-local
    if ((g[0] & 0xff00) === 0xff00) return 'local'; // multicast
    if ((g[0] & 0xfe00) === 0xfc00) return 'private'; // unique-local fc00::/7
    if ((g[0] & 0xffc0) === 0xfec0) return 'private'; // deprecated site-local
    return 'public';
}

/** The canonical form and class of an address as a log wrote it, or null if it is not one. */
export function parseAddress(raw: unknown): Address | null {
    if (typeof raw !== 'string' && typeof raw !== 'number') return null;
    let s = String(raw).trim();
    if (s.startsWith('[') && s.endsWith(']')) s = s.slice(1, -1);
    if (!s) return null;
    const v4 = parseV4(s);
    if (v4) return { ip: v4.join('.'), version: 'ipv4', cls: classifyV4(v4) };
    const v6 = parseV6(s);
    if (!v6) return null;
    // IPv4-mapped (::ffff:a.b.c.d) is how Sysmon writes an A record; it is the IPv4 address.
    if (v6.slice(0, 5).every((x) => x === 0) && v6[5] === 0xffff) {
        const o = [v6[6] >> 8, v6[6] & 0xff, v6[7] >> 8, v6[7] & 0xff];
        return { ip: o.join('.'), version: 'ipv4', cls: classifyV4(o) };
    }
    return { ip: formatV6(v6), version: 'ipv6', cls: classifyV6(v6) };
}

// ---- names -----------------------------------------------------------------------------------

/**
 * The Domain type's own validator (typepack-basic `infrastructure.json`). Checked here because the
 * host refuses a create that fails it by throwing, and one bad name must not cost the whole run.
 */
const DOMAIN_RE = /^[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}$/;

/**
 * Suffixes that only ever resolve inside someone's network. `.home` and `.corp` are not reserved,
 * but ICANN has deferred them indefinitely for exactly this reason: they are what internal
 * resolvers already answer for.
 */
const INTERNAL_SUFFIXES = [
    'local',
    'localhost',
    'localdomain',
    'lan',
    'home',
    'corp',
    'internal',
    'intranet',
    'private',
    'home.arpa',
];

export type NameClass = 'public' | 'internal' | 'reverse' | 'address' | 'invalid';

export interface Name {
    /** Lower case, no trailing dot. */
    name: string;
    cls: NameClass;
    /** Whether the Domain type accepts it. An internal name may (`nas.home`) or may not (`wpad`). */
    valid: boolean;
}

export function parseName(raw: unknown): Name | null {
    if (typeof raw !== 'string') return null;
    let s = raw.trim().toLowerCase();
    while (s.endsWith('.')) s = s.slice(0, -1);
    if (!s) return null;
    const valid = DOMAIN_RE.test(s) && !s.split('.').some((l) => l === '');
    if (parseAddress(s)) return { name: s, cls: 'address', valid: false };
    // A PTR query names an address, not a domain anyone registered.
    if (s.endsWith('.in-addr.arpa') || s.endsWith('.ip6.arpa')) return { name: s, cls: 'reverse', valid };
    if (!s.includes('.') || INTERNAL_SUFFIXES.some((x) => s === x || s.endsWith(`.${x}`))) {
        return { name: s, cls: 'internal', valid };
    }
    return { name: s, cls: valid ? 'public' : 'invalid', valid };
}
