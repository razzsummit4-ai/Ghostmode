import http from 'node:http';
import os from 'node:os';
import { config } from './config.js';
import { logger } from './logger.js';
import { connect, disconnect } from './db.js';
import { createApp } from './app.js';
import { attachSocketGateway } from './socket/index.js';
import { startDiscovery } from './lib/discovery.js';

/**
 * Every non-internal IPv4 address this machine holds.
 *
 * The server binds all interfaces so a phone on the same Wi-Fi can reach it,
 * and the user has to type one of these addresses into the app. Printing them
 * on startup saves them working it out, and it is the single most common
 * reason a LAN install appears to fail.
 */
function lanAddresses() {
  return Object.values(os.networkInterfaces())
    .flat()
    .filter((n) => n && n.family === 'IPv4' && !n.internal)
    .map((n) => n.address);
}

/**
 * Ask whatever is already answering on [port] to identify itself.
 *
 * This turns "EADDRINUSE" - which tells you nothing - into "the thing on port
 * 4000 is a service called ghost-chat, not SecureChat", which is the actual
 * problem. An app pointed at that address gets real HTTP answers from the wrong
 * program, so every sign-up, sign-in and OTP request comes back as a 404 that
 * looks like a bug in this project rather than a port that was never ours.
 */
async function identifyOccupant(port) {
  try {
    const res = await fetch(`http://127.0.0.1:${port}/health`, {
      signal: AbortSignal.timeout(2000),
    });
    const body = await res.json().catch(() => null);
    const service = body?.service ?? body?.name ?? null;
    return { status: res.status, service: typeof service === 'string' ? service : null };
  } catch {
    // Something holds the port but does not speak our protocol (or is silent).
    return { status: null, service: null };
  }
}

/** A message a person can act on, rather than a bare EADDRINUSE. */
function portConflictMessage(port, occupant, tried) {
  const who = occupant.service
    ? `It answers as "${occupant.service}"`
    : occupant.status
      ? `It answered /health with HTTP ${occupant.status} but did not identify itself`
      : 'It accepted the connection but never answered';
  const lines = [
    `Port ${port} is already in use by another process, so SecureChat cannot start`,
    `on the address the app expects (${who}).`,
    '',
    'Find it and stop it, from an elevated terminal:',
    `    netstat -ano | findstr :${port}`,
    '    taskkill /PID <the number in the last column> /F',
    '',
    'or start SecureChat somewhere else and tell the app:',
    `    PORT=4100 npm start      (then enter http://<this-computer>:4100 in the app)`,
  ];
  if (tried > 1) {
    lines.push('', `Ports ${port}-${port + tried - 1} were all busy.`);
  }
  return lines.join('\n');
}

/**
 * Bind to the first free port at or after [preferredPort].
 *
 * A second server on the same machine - a leftover dev process, or an unrelated
 * project that grabbed the same port - is the most common reason a correctly
 * built app "cannot sign in". Rather than dying with EADDRINUSE after the
 * database has already started, move on, say so loudly, and advertise the real
 * port over discovery so phones are never sent to the wrong service.
 */
async function bind(server, preferredPort, maxTries = 10) {
  for (let attempt = 0; attempt < maxTries; attempt += 1) {
    const port = preferredPort + attempt;
    try {
      await new Promise((resolve, reject) => {
        const onError = (err) => {
          server.removeListener('error', onError);
          reject(err);
        };
        server.once('error', onError);
        server.listen(port, '0.0.0.0', () => {
          server.removeListener('error', onError);
          resolve();
        });
      });
      return port;
    } catch (err) {
      if (err.code !== 'EADDRINUSE') throw err;

      const occupant = await identifyOccupant(port);
      logger.warn('server.port_in_use', { port, ...occupant });

      if (occupant.service === 'securechat') {
        throw new Error(
          `A SecureChat server is already running on port ${port}. Use that one, ` +
            'or stop it first - two servers on one machine would fight over the ' +
            'same database and give the app two different sets of accounts.',
        );
      }
      if (!config.PORT_AUTO_FALLBACK) {
        throw new Error(portConflictMessage(port, occupant, 1));
      }
      if (attempt === maxTries - 1) {
        throw new Error(portConflictMessage(preferredPort, occupant, maxTries));
      }
      logger.warn('server.port_fallback', { from: port, to: port + 1 });
    }
  }
  throw new Error(portConflictMessage(preferredPort, { status: null, service: null }, maxTries));
}

/** What to print once a phone could plausibly connect. */
function devBanner(port) {
  const lines = ['', '  SecureChat is listening.', ''];
  if (port !== config.PORT) {
    lines.push(
      `  NOTE: port ${config.PORT} was taken by another program, so this server`,
      `  is on port ${port} instead. Any app still pointed at ${config.PORT}`,
      '  is talking to that other program, not to SecureChat.',
      '',
    );
  }
  if (config.DISCOVERY_ENABLED) {
    lines.push(
      '  Open the app on a phone on this same Wi-Fi: it will find this',
      `  server automatically (UDP ${config.DISCOVERY_PORT}).`,
      '',
    );
  }
  lines.push(
    '  To point the app here by hand, enter one of these',
    '  (app -> Server address):',
    '',
  );
  for (const address of lanAddresses()) {
    lines.push(`    http://${address}:${port}`);
  }
  lines.push(`    http://10.0.2.2:${port}   (Android emulator only)`);
  lines.push('');
  lines.push('  Sign up once with a phone number and password, then sign in');
  lines.push('  with the same details. A number can only be registered once.');
  lines.push('');
  if (config.STORAGE_DRIVER === 'local') {
    lines.push('  Media is stored on this machine under ./var/media.');
    lines.push('');
  }
  return lines.join('\n');
}



async function main() {
  await connect();

  const app = createApp();
  const server = http.createServer(app);
  attachSocketGateway(server, app);

  // Long-poll clients may hold sockets open; give them time to drain.
  server.keepAliveTimeout = 65_000;
  server.headersTimeout = 70_000;

  // Bind first, announce second: discovery has to advertise the port actually
  // obtained, not the one requested.
  const port = await bind(server, config.PORT);

  // Announce this server on the LAN so a phone can find it without being told
  // an IP address. Safe to fail: the app falls back to manual entry.
  const discovery = startDiscovery({ httpPort: port });

  logger.info('server.listening', {
    port,
    requested: config.PORT,
    env: config.NODE_ENV,
    storage: config.STORAGE_DRIVER,
    auth: 'password',
  });

  // Development only: tell the operator exactly what to type into the app.
  if (!config.isProd) {
    // eslint-disable-next-line no-console
    console.log(devBanner(port));
  }

  const shutdown = async (signal) => {
    logger.info('server.shutdown', { signal });
    discovery.stop();
    server.close();
    await disconnect();
    process.exit(0);
  };
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
}

main().catch((err) => {
  logger.error('server.boot_failed', { err: err.message });
  // The errors raised above are written for a person to act on; a single JSON
  // log line in a busy terminal is how they get missed.
  if (err.message) {
    // eslint-disable-next-line no-console
    console.error(`\n${err.message}\n`);
  }
  process.exit(1);
});

