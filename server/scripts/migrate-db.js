#!/usr/bin/env node
/**
 * Copy a SecureChat database from one MongoDB to another - normally the local
 * embedded database to MongoDB Atlas.
 *
 * Why this exists: switching MONGODB_URI to a fresh Atlas cluster does not fail
 * loudly, it just starts empty. Every account silently disappears, phones get
 * 401 on their stored token, and the user concludes the app is broken. The
 * document store holds accounts, public key bundles, message ciphertext and
 * group rosters, so it is worth carrying over even in development.
 *
 * Nothing here is plaintext - the server is zero-knowledge and so is this dump.
 * The source is never modified.
 *
 *   node scripts/migrate-db.js --dry-run              # compare, copy nothing
 *   node scripts/migrate-db.js                        # embedded -> MONGODB_URI
 *   node scripts/migrate-db.js --to="mongodb+srv://…other database…"
 *   node scripts/migrate-db.js --force                # target already has data
 *
 * Attachment BLOBS are not in the database: with STORAGE_DRIVER=local they are
 * files under server/var/media, and with STORAGE_DRIVER=s3 they live in the
 * bucket. Copy those separately; the database only holds their metadata.
 */
import mongoose from 'mongoose';
import { config } from '../src/config.js';

const flag = (name) => {
  const inline = process.argv.find((a) => a.startsWith(`--${name}=`));
  if (inline) return inline.slice(name.length + 3);
  return process.argv.includes(`--${name}`) ? true : undefined;
};

const dryRun = flag('dry-run') === true;
const force = flag('force') === true;

// With AUTO_DB=embedded the data lives in a mongod owned by the running server
// process. Dial that instead of starting a second one, which would collide with
// the first on EMBEDDED_DB_PORT and fail in a way that looks like a script bug.
const defaultFrom =
  config.AUTO_DB === 'embedded'
    ? `mongodb://127.0.0.1:${config.EMBEDDED_DB_PORT}/securechat`
    : config.MONGODB_URI;

const from = flag('from') || defaultFrom;
const to = flag('to') || config.MONGODB_URI;

const label = (uri) => uri.replace(/(:\/\/[^:]+:)[^@]*@/, '$1••••@');
const die = (msg) => {
  console.error(`\nABORTED  ${msg}\n`);
  process.exit(1);
};

// Compare what the two URIs actually point at (host + database), ignoring
// credentials and options, so "--to" that silently duplicates the source is
// caught before anything is written.
const fingerprint = (uri) => {
  const u = new URL(uri.replace(/^mongodb(\+srv)?:\/\//, 'http://'));
  return `${u.host}${u.pathname}`.replace(/\/$/, '');
};
if (fingerprint(from) === fingerprint(to)) {
  die('source and target are the same database, so there is nothing to copy.');
}

if (config.AUTO_DB === 'embedded' && !flag('from')) {
  console.log(
    'Reading from the embedded database on this machine. That mongod belongs to\n' +
      'the running SecureChat server, so keep the server up while this runs.\n',
  );
}

console.log(`source  ${label(from)}`);
console.log(`target  ${label(to)}`);
if (dryRun) console.log('mode    dry run - nothing will be written\n');

// A failed connection must read as "the target is not reachable: <cause>", not
// as a stack trace from inside the driver - this script is what people run when
// Atlas will not accept them, so it has to be the thing that explains it.
const open = async (uri, which, timeoutMs) => {
  try {
    return await mongoose.createConnection(uri, { serverSelectionTimeoutMS: timeoutMs }).asPromise();
  } catch (err) {
    die(`${which} database is not reachable (${err.message}). Run npm run check:db for a diagnosis.`);
  }
};

const source = await open(from, 'source', 10_000);
const target = await open(to, 'target', 15_000);

const collections = (await source.db.listCollections().toArray())
  .map((c) => c.name)
  .filter((name) => !name.startsWith('system.'))
  .sort();

if (collections.length === 0) {
  await Promise.all([source.close(), target.close()]);
  die(
    'the source database has no collections at all. Either the server has never\n' +
      '         run against it, or the URI names the wrong database.',
  );
}

// Refuse to blend into a database that already holds data. Two user documents
// for one phone number, from two different origins, is the kind of corruption
// that surfaces months later as an account that cannot sign in.
if (!dryRun && !force) {
  let existing = 0;
  for (const name of collections) {
    existing += await target.db.collection(name).countDocuments();
  }
  if (existing > 0) {
    await Promise.all([source.close(), target.close()]);
    die(
      `the target already holds ${existing} document(s) in these collections.\n` +
        '         Point --to at an empty database, or rerun with --force to add to it.',
    );
  }
}

const BATCH = 500;
let grandTotal = 0;
let failures = 0;

/**
 * Index options worth carrying across.
 *
 * Only keys the driver actually set are copied: an index that is not unique
 * comes back without the field, and handing `unique: undefined` to the server
 * arrives as `unique: null`, which mongod rejects with a TypeMismatch - a copy
 * script that dies on its own bookkeeping is worse than no copy script.
 */
function indexOptions(idx) {
  const options = { name: idx.name };
  for (const key of ['unique', 'sparse', 'expireAfterSeconds', 'partialFilterExpression']) {
    if (idx[key] !== undefined && idx[key] !== null) options[key] = idx[key];
  }
  return options;
}

async function copyCollection(name) {
  const src = source.db.collection(name);
  const dst = target.db.collection(name);
  const expected = await src.countDocuments();

  if (dryRun) {
    grandTotal += expected;
    console.log(`  ${name.padEnd(18)} ${String(expected).padStart(7)}  (would copy)`);
    return;
  }

  // Indexes before data: a unique index has to be in place while the insert
  // runs, and TTL indexes (login locks, OTP challenges) are behaviour, not
  // decoration - without them stale rows simply never disappear.
  for (const idx of await src.indexes()) {
    if (idx.name === '_id_') continue;
    try {
      await dst.createIndex(idx.key, indexOptions(idx));
    } catch (err) {
      // An index that already exists with different options is a warning, not a
      // reason to abandon the copy: the documents are what matters, and the
      // server rebuilds its own indexes on boot.
      console.log(`        note: index ${idx.name} not recreated (${err.codeName || err.message})`);
    }
  }

  let batch = [];
  for await (const doc of src.find({}, { batchSize: BATCH }).sort({ _id: 1 })) {
    batch.push(doc);
    if (batch.length >= BATCH) await dst.insertMany(batch.splice(0, BATCH), { ordered: false });
  }
  if (batch.length) await dst.insertMany(batch, { ordered: false });

  const landed = await dst.countDocuments();
  const match = landed === expected;
  if (!match) failures += 1;
  grandTotal += landed;
  console.log(
    `  ${name.padEnd(18)} ${String(expected).padStart(7)} -> ${String(landed).padStart(7)}` +
      `  ${match ? 'ok' : 'MISMATCH'}`,
  );
}

for (const name of collections) {
  try {
    await copyCollection(name);
  } catch (err) {
    await Promise.all([source.close(), target.close()]);
    die(`copying "${name}" failed: ${err.message}`);
  }
}

await Promise.all([source.close(), target.close()]);

console.log(`\n${dryRun ? 'Would copy' : 'Copied'} ${grandTotal} documents.`);

if (failures) {
  console.log(`${failures} collection(s) did not land completely - do not switch yet.\n`);
  process.exitCode = 1;
} else if (dryRun) {
  console.log('Rerun without --dry-run to copy for real.\n');
} else {
  console.log(
    '\nNEXT  1. stop the server (anything still writing to the old database would\n' +
        '         leave rows behind, since the copy is a snapshot),\n' +
        '      2. set AUTO_DB=mongo and MONGODB_URI to the target in server/.env,\n' +
        '      3. npm run check:db, then start the server.\n' +
        '\n      _ids were preserved, so tokens issued to phones keep working and no\n' +
        '      device has to re-register. Copy server/var/media separately: encrypted\n' +
        '      attachment bytes are files on disk, not database documents.\n',
  );
}

