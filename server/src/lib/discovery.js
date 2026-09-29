import dgram from 'node:dgram';
import os from 'node:os';
import { logger } from '../logger.js';
import { config } from '../config.js';

/**
 * LAN discovery responder.
 *
 * A phone on the same Wi-Fi has no way to learn where the server is: the APK is
 * built once and distributed to everyone, so no address can be compiled in. UDP
 * broadcast solves this without a DNS name, a QR code, or the user reading an
 * IP off a terminal.
 *
 * Protocol, deliberately tiny and one-way:
 *   probe   "SECURECHAT/1 DISCOVER"           (client -> broadcast)
 *   answer  {"service":"securechat", ...}     (server -> client)
 *
 * The answer advertises PUBLIC addresses only. No key material, no user data and
 * no message content crosses this channel - it exists purely to answer "where
 * is the server".
 */
const PROBE = 'SECURECHAT/1 DISCOVER';
const ANNOUNCE_INTERVAL_MS = 5_000;

/** Every non-internal IPv4 address this machine holds. */
function lanAddresses() {
  return Object.values(os.networkInterfaces())
    .flat()
    .filter((n) => n && n.family === 'IPv4' && !n.internal)
    .map((n) => n.address);
}

/** The /24 broadcast address for a given host, used for directed discovery. */
function subnetBroadcast(address) {
  const parts = address.split('.');
  if (parts.length !== 4) return '255.255.255.255';
  return `${parts[0]}.${parts[1]}.${parts[2]}.255`;
}

/**
 * Start the responder.
 *
 * Binds to all interfaces with `broadcast: true` and `reuseAddr` so it works on
 * Windows, macOS and Linux without elevated privileges.
 */
export function startDiscovery({ httpPort = config.PORT } = {}) {
  if (!config.DISCOVERY_ENABLED) {
    logger.info('discovery.disabled');
    return { stop() {} };
  }

  const socket = dgram.createSocket({ type: 'udp4', reuseAddr: true });

  // [httpPort] must be the port actually bound. If the requested one was already
  // taken and the server moved on, advertising the configured port points every
  // phone at whatever unrelated service holds it - which is far worse than the
  // app not finding a server at all.
  const details = () => ({
    service: 'securechat',
    version: 1,
    name: config.DISCOVERY_NAME,
    httpPort,
    // Sorted so the client can present a stable list.
    addresses: [...new Set(lanAddresses())].sort(),
    publicUrl: config.PUBLIC_URL,
  });

  const announcement = () => {
    const payload = Buffer.from(JSON.stringify(details()));

    // Global broadcast, plus one directed broadcast per interface. Routers and
    // Wi-Fi access points frequently drop the global form, so sending both
    // makes discovery work on more real networks.
    const targets = new Set(['255.255.255.255']);
    for (const address of lanAddresses()) targets.add(subnetBroadcast(address));

    for (const target of targets) {
      socket.send(payload, config.DISCOVERY_PORT, target, (err) => {
        // A failed broadcast on one interface must not stop the others.
        if (err) logger.debug('discovery.announce_failed', { target });
      });
    }
  };

  socket.on('message', (msg, rinfo) => {
    if (msg.toString('utf8').trim() !== PROBE) return;
    const reply = Buffer.from(JSON.stringify(details()));
    // Answer the probe directly, which works even where broadcast is filtered.
    socket.send(reply, rinfo.port, rinfo.address, (err) => {
      if (err) logger.debug('discovery.reply_failed', { to: rinfo.address });
    });
  });

  socket.on('error', (err) => {
    // Discovery is a convenience. If the port is taken or UDP is unavailable the
    // server must still serve HTTP, so this is logged and never fatal.
    logger.warn('discovery.socket_error', { err: err.message });
    try {
      socket.close();
    } catch {
      /* already closed */
    }
  });

  socket.bind(config.DISCOVERY_PORT, () => {
    try {
      socket.setBroadcast(true);
    } catch (err) {
      logger.debug('discovery.broadcast_unavailable', { err: err.message });
    }
    logger.info('discovery.listening', { port: config.DISCOVERY_PORT });
    announcement();
  });

  const timer = setInterval(announcement, ANNOUNCE_INTERVAL_MS);
  // Do not hold the event loop open on shutdown.
  timer.unref?.();

  return {
    stop() {
      clearInterval(timer);
      try {
        socket.close();
      } catch {
        /* already closed */
      }
    },
  };
}
