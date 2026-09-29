import fs from 'node:fs';
import path from 'node:path';
import mongoose from 'mongoose';
import { config } from './config.js';
import { logger } from './logger.js';

mongoose.set('strictQuery', true);

/**
 * Note: do NOT enable `sanitizeFilter` globally. It rewrites nested query
 * objects and turns legitimate Mongo operators such as `{ $gte: date }` into
 * literal values, breaking every range query. Input validation is handled at
 * the edge with zod, and schemas use `strict: 'throw'`.
 */

let connection = null;

/** The embedded mongod process, when one is running. */
let embedded = null;

/**
 * Start a local mongod for this process.
 *
 * This exists so a self-hoster can run SecureChat with one command and no
 * separate database install. The data directory is on disk, so messages
 * survive a restart exactly as they would with a managed instance.
 *
 * The server is still zero-knowledge here: running the database locally changes
 * who can reach it, not what it can read. It holds ciphertext only.
 */
async function startEmbeddedMongo() {
  // Imported lazily so a deployment using a real MongoDB never pays for it.
  const { MongoMemoryServer } = await import('mongodb-memory-server');

  const dbPath = path.resolve(config.EMBEDDED_DB_DIR);
  fs.mkdirSync(dbPath, { recursive: true });

  logger.info('mongo.embedded_starting', { dataDir: dbPath });

  // mongod journals and preallocates aggressively, so it is one of the worst
  // things to put on a syncing drive: OneDrive/Dropbox intercept every write and
  // a boot that takes a second locally takes half a minute here. Say so, rather
  // than letting the user conclude that signing in is broken.
  if (/[\\/](onedrive|dropbox|google[ -]?drive|icloud drive)[\\/]/i.test(dbPath)) {
    logger.warn('mongo.embedded_on_synced_drive', {
      dataDir: dbPath,
      hint: 'set EMBEDDED_DB_DIR outside the sync root (e.g. C:\\temp\\securechat-db) for far faster startup',
    });
  }

  // `instance.launchTimeout` is the option mongodb-memory-server v10 actually
  // reads. The name it replaced (`startupTimeout`) is silently ignored, which
  // pins the wait at the library's own 10 s default and yields the cryptic
  // `Instance failed to start within 10000ms` on a slow or scanned disk. The
  // obsolete key is kept alongside it so the fix holds on older releases too.
  try {
    embedded = await MongoMemoryServer.create({
      startupTimeout: config.EMBEDDED_DB_LAUNCH_TIMEOUT_MS,
      instance: {
        port: config.EMBEDDED_DB_PORT,
        dbName: 'securechat',
        dbPath,
        storageEngine: 'wiredTiger',
        launchTimeout: config.EMBEDDED_DB_LAUNCH_TIMEOUT_MS,
      },
    });
  } catch (err) {
    throw new Error(
      `The embedded database did not come up within ` +
        `${config.EMBEDDED_DB_LAUNCH_TIMEOUT_MS} ms (${err.message}). Either start ` +
        `a MongoDB of your own and set MONGO_URI, or point EMBEDDED_DB_DIR at a ` +
        `folder that is not synced by OneDrive/Dropbox.`,
      { cause: err },
    );
  }

  logger.info('mongo.embedded_ready', { uri: embedded.getUri() });
  return embedded.getUri('securechat');
}

export async function connect(uri = config.MONGODB_URI, { quiet = false } = {}) {
  if (connection) return connection;

  let target = uri;
  if (config.AUTO_DB === 'embedded' && uri === config.MONGODB_URI) {
    // AUTO_DB=embedded wins over MONGODB_URI, and that precedence is a trap: paste
    // an Atlas URI, forget to flip the switch, and the server runs perfectly well
    // on the old local database while every account the user ever created appears
    // to have vanished. Say so at startup instead of quietly ignoring the URI.
    // The URI itself is never logged - it carries the database password.
    if (/^mongodb\+srv:/.test(config.MONGODB_URI)) {
      logger.warn('mongo.uri_ignored', {
        reason: 'AUTO_DB is "embedded"',
        hint: 'set AUTO_DB=mongo in server/.env to use the Atlas URI, after npm run check:db',
      });
    }
    target = await startEmbeddedMongo();
  }

  connection = await mongoose.connect(target, {
    serverSelectionTimeoutMS: 10_000,
    maxPoolSize: 50,
    autoIndex: config.isProd ? false : true,
  });
  if (!quiet) logger.info('mongo.connected', { db: mongoose.connection.name });
  mongoose.connection.on('error', (err) => logger.error('mongo.error', { err: err.message }));
  mongoose.connection.on('disconnected', () => logger.warn('mongo.disconnected'));
  return connection;
}

export async function disconnect() {
  if (connection) {
    await mongoose.disconnect();
    connection = null;
  }
  // Shut the embedded instance down too, so a restart does not hit a port clash.
  if (embedded) {
    await embedded.stop();
    embedded = null;
  }
}

export function isConnected() {
  return mongoose.connection.readyState === 1;
}

