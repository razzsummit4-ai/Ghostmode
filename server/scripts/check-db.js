#!/usr/bin/env node
/**
 * Answers one question before the server is restarted: can this machine reach
 * that database, and is what it reached the database you meant?
 *
 * A failing database connection is the worst kind of failure in this project,
 * because the server refuses to boot without one and the symptom the user sees
 * is "sign-in does not work". MongoDB and Atlas also report almost every network
 * problem as `Server selection timed out after 10000 ms`, which sends people
 * hunting for a code bug when the real cause is a missing IP in the Atlas
 * allowlist or an `@` left un-encoded in the password. So this script separates
 * the layers - URI shape, DNS, reachability, credentials, permissions - and
 * names the layer that broke.
 *
 *   node scripts/check-db.js                        # test MONGODB_URI from .env
 *   node scripts/check-db.js "mongodb+srv://..."    # test a URI before saving it
 *   node scripts/check-db.js --wait=60              # retry for 60 s (new cluster)
 *
 * It never writes. Safe to run against production.
 */
import dns from 'node:dns/promises';
import mongoose from 'mongoose';
import { config } from '../src/config.js';

const argv = process.argv.slice(2);
const waitOpt = argv.find((a) => a.startsWith('--wait'));
const waitUntil = Number(waitOpt?.split('=')[1] ?? 0);
const positional = argv.find(
  (a) => a.startsWith('mongodb://') || a.startsWith('mongodb+srv://'),
);
const uri = positional || config.MONGODB_URI;
const usingEnv = !positional;

const ok = (label, extra = '') => console.log(`PASS  ${label}${extra ? `  ${extra}` : ''}`);
const bad = (label, extra = '') => console.log(`FAIL  ${label}${extra ? `  ${extra}` : ''}`);
const note = (text) => console.log(`      ${text}`);

/**
 * The address Atlas will see this machine as.
 *
 * Printed because the fix for the commonest Atlas error is "add your IP to
 * Network Access", and a person on a router has no way to know which address
 * that means - especially when the ISP renumbers it every few weeks.
 */
async function publicAddress() {
  try {
    const res = await fetch('https://api.ipify.org?format=json', {
      signal: AbortSignal.timeout(4000),
    });
    const body = await res.json();
    return typeof body?.ip === 'string' ? body.ip : null;
  } catch {
    return null; // offline, or the resolver is down - not important here
  }
}

/** Static checks on the string itself, before any network call is wasted. */
function inspectUri(value) {
  const problems = [];
  const srv = value.startsWith('mongodb+srv://');
  if (!srv && !value.startsWith('mongodb://')) {
    return {
      problems: [
        'not a MongoDB connection string (must start mongodb:// or mongodb+srv://)',
      ],
      host: null,
      srv,
    };
  }

  const rest = value.slice(value.indexOf('://') + 3);
  const host = rest.slice(rest.lastIndexOf('@') + 1).split('/')[0].split('?')[0];
  const hostOnly = host.split(':')[0];

  // Credentials end at the FIRST '@'. More than one means an un-encoded '@' in
  // the password, which silently mangles the hostname and then fails as a
  // timeout - the single most common Atlas paste error.
  const ats = (rest.match(/@/g) || []).length;
  if (ats > 1) {
    problems.push(
      'the URI has more than one "@" - the password needs URL-encoding (@ -> %40). ' +
        "Atlas shows the encoded form on its own Connect page; copy that one.",
    );
  }
  // Only a hosted cluster demands credentials: a local or embedded mongod
  // legitimately has none, and refusing it here would break `npm run check:db`
  // for anyone still on the local database.
  if (ats === 0 && (srv || hostOnly.endsWith('.mongodb.net'))) {
    problems.push('no username:password in the URI - an Atlas cluster always requires one');
  }

  if (/x{3,}|your[-_]?(cluster|host|uri)|<.*>|\.{3}/.test(host)) {
    problems.push(
      `the host "${host}" still looks like a placeholder - paste the real URI from ` +
        'Atlas (Connect -> Drivers -> Node.js), whose cluster name is 7 random characters',
    );
  }
  if (srv && !host.endsWith('.mongodb.net')) {
    note(`note: SRV host is "${host}" - Atlas hosts end in .mongodb.net`);
  }
  return { problems, host, srv };
}

/** Resolve the SRV record Atlas publishes its real node addresses through. */
async function resolveSrv(host) {
  try {
    const records = await dns.resolveSrv(`_mongodb._tcp.${host}`);
    return { hosts: records.map((r) => `${r.name}:${r.port}`) };
  } catch (err) {
    return { error: err };
  }
}

/** Turn MongoDB's one-size-fits-all timeout into the likely actual cause. */
function explain(err, ip) {
  const m = `${err.message} ${err.cause?.message ?? ''} ${err.cause?.cause?.message ?? ''}`;
  if (/authentication (failed|error)|MongoDBCredential|InvalidCredentials|auth failed/i.test(m)) {
    return [
      'credentials rejected. In Atlas: Security -> Database Access - confirm the user',
      "exists and the password matches, then regenerate the URI so the encoding is Atlas's own.",
    ];
  }
  if (/not authorized|Unauthorized|command denied|shardkey/i.test(m)) {
    return ['the user exists but lacks read/write permission on this database.'];
  }
  if (/querySrv|getaddrinfo|ENOTFOUND|EAI_AGAIN/i.test(m)) {
    return [
      'DNS could not resolve the cluster: wrong hostname, a cluster still being created,',
      'or a network that blocks the SRV lookups Atlas depends on.',
    ];
  }
  if (/timed out|ECONNREFUSED|ETIMEDOUT|ECONNRESET|ENETUNREACH|socket hang up/i.test(m)) {
    return [
      'nothing answered. With Atlas this is nearly always the Network Access allowlist:',
      ip
        ? `  add ${ip} - or 0.0.0.0/0 for any address - and wait ~60 s to apply.`
        : "  add this machine's public IP, or 0.0.0.0/0 for any address, then wait ~60 s.",
      'next: a paused or still-provisioning cluster behaves exactly the same (M0 pauses',
      'after 30 days without use, and needs a click to wake).',
    ];
  }
  if (/SSL|TLS|certificate/i.test(m)) {
    return ['TLS problem - check the system clock, and whether a proxy intercepts TLS.'];
  }
  return [err.message];
}

/** Everything, once. Returns true when the database is usable. */
async function attempt() {
  const { problems, host, srv } = inspectUri(uri);
  console.log(`\nTarget   ${uri.replace(/(:\/\/[^:]+:)[^@]*@/, '$1••••@')}`);
  note(usingEnv ? 'source   MONGODB_URI from server/.env' : 'source   command line');

  if (problems.length) {
    for (const p of problems) bad('connection string', p);
    return false;
  }
  ok('connection string');

  if (srv) {
    const { hosts, error } = await resolveSrv(host);
    if (error) {
      bad('DNS SRV lookup', `${error.code || error.message} on _mongodb._tcp.${host}`);
      note('a cluster that does not exist and a typo in its name fail identically');
      return false;
    }
    ok('DNS SRV lookup', hosts.join(', '));
  }

  try {
    await mongoose.connect(uri, { serverSelectionTimeoutMS: 10_000, maxPoolSize: 2 });
  } catch (err) {
    bad('connect', err.name);
    const ip = await publicAddress();
    for (const line of explain(err, ip)) note(line);
    return false;
  }

  const conn = mongoose.connection;
  const [build, collections] = await Promise.all([
    conn.db.admin().command({ buildInfo: 1 }),
    conn.db.listCollections().toArray(),
  ]);
  ok('handshake and credentials', `MongoDB ${build.version}, database "${conn.db.databaseName}"`);

  const servers = conn.client?.topology?.description?.servers;
  const topology = [...(servers?.values?.() ?? [])]
    .map((s) => `${s.address} (${s.type?.name ?? s.type})`)
    .join(', ');
  if (topology) ok('cluster members', topology);

  if (collections.length === 0) {
    note('database is empty - normal for a new cluster; the server creates its');
    note('collections and indexes the first time it boots against it.');
  }
  for (const c of collections.slice(0, 12)) {
    const n = await conn.db.collection(c.name).countDocuments();
    note(`${c.name.padEnd(16)} ${n} documents`);
  }
  if (collections.length > 12) note(`...and ${collections.length - 12} more collections`);

  await mongoose.disconnect();

  if (config.AUTO_DB === 'embedded') {
    console.log(
      '\nNEXT  AUTO_DB is "embedded", so the server IGNORES this URI and starts its own\n' +
        '      local mongod instead. To actually use the database you just tested, set\n' +
        '      AUTO_DB=mongo in server/.env and restart the server.',
    );
  }
  return true;
}

const deadline = Date.now() + waitUntil * 1000;
let passed = false;
for (;;) {
  try {
    passed = await attempt();
  } finally {
    if (mongoose.connection.readyState !== 0) await mongoose.disconnect().catch(() => {});
  }
  if (passed || Date.now() >= deadline) break;
  console.log('\nretrying in 10 s - a brand new Atlas cluster takes minutes to accept links');
  await new Promise((r) => setTimeout(r, 10_000));
}

console.log(
  passed
    ? '\nThe database is reachable. The server can use it.\n'
    : '\nDatabase check FAILED. The server will not start until it passes.\n',
);
if (!passed) process.exitCode = 1;

