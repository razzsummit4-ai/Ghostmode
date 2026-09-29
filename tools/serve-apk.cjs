// Tiny static file server for handing the APKs to phones on the same Wi-Fi.
//
// Serves ONLY the APKs and their checksums, read from an explicit allowlist
// derived from what is actually in dist/. Nothing else on disk is reachable, so
// this never exposes the source tree or server/.env.
//
// Binds to all interfaces so a phone on the LAN can reach it, and serves a
// plain landing page at / so a user opening the address in a browser can pick
// the right build instead of guessing a filename.
//
// Run detached; stop by killing the node process.

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

// Serve the project-root dist/ directory, which is the parent of tools/.
const ROOT = path.join(__dirname, '..', 'dist');
const PORT = Number(process.env.PORT || 8080);

const MIME = {
  '.apk': 'application/vnd.android-package-archive',
  '.sha256': 'text/plain; charset=utf-8',
  '.sha1': 'text/plain; charset=utf-8',
};

// Which build suits which device. An unknown APK still downloads; this only
// labels the landing page.
const NOTES = {
  'SecureChat-1.0.0.apk': 'Universal - works on every device. Start here.',
  'SecureChat-arm64-v8a.apk': 'Most modern phones. Smallest download.',
  'SecureChat-armeabi-v7a.apk': 'Older 32-bit phones.',
  'SecureChat-x86_64.apk': 'Emulators only.',
};

// Build the allowlist from the files that actually exist, rather than a
// hand-maintained list that silently goes stale after a rebuild.
const allowed = new Set();
try {
  for (const entry of fs.readdirSync(ROOT)) {
    if (entry.endsWith('.apk') || entry.endsWith('.sha256') || entry.endsWith('.sha1')) {
      allowed.add(entry);
    }
  }
} catch {
  console.error(`Cannot read ${ROOT}. Run the APK build first.`);
  process.exit(1);
}

const apks = [...allowed].filter((f) => f.endsWith('.apk')).sort();
if (apks.length === 0) {
  console.error('No APKs found in dist/. Run the APK build first.');
  process.exit(1);
}

/** A minimal landing page, so a browser visit is useful. */
function landingPage() {
  const rows = apks
    .map((name) => {
      const mb = (fs.statSync(path.join(ROOT, name)).size / (1024 * 1024)).toFixed(1);
      const note = NOTES[name] || '';
      return (
        `<li><a href="/${name}">${name}</a>` +
        `<span class="s">${mb} MB</span>` +
        (note ? `<span class="n">${note}</span>` : '') +
        `</li>`
      );
    })
    .join('\n');

  return `<!doctype html>
<html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SecureChat download</title>
<style>
 body{background:#0B141A;color:#E9EDEF;font:16px system-ui,sans-serif;margin:0;padding:28px 20px}
 h1{color:#00A884;font-size:22px;margin:0 0 6px}
 p{color:#8696A0;font-size:14px;line-height:1.5;margin:0 0 20px}
 ul{list-style:none;padding:0;max-width:560px}
 li{background:#1F2C34;border-radius:10px;padding:14px 16px;margin-bottom:10px}
 a{color:#53BDEB;text-decoration:none;font-size:15px;font-weight:600}
 .s{color:#8696A0;font-size:13px;margin-left:8px}
 .n{display:block;color:#8696A0;font-size:12.5px;margin-top:4px}
 .warn{background:#2a2416;border:1px solid #FFD279;color:#FFD279;padding:12px 14px;
       border-radius:10px;font-size:13px;line-height:1.5;max-width:560px;margin-top:18px}
</style></head><body>
<h1>SecureChat</h1>
<p>End-to-end encrypted messenger. Download, allow installs from your browser, then open the file.</p>
<ul>
${rows}
</ul>
<p class="warn">After installing, open the app and set the server address to the
machine running the SecureChat backend, for example
<b>http://192.168.0.100:4000</b>.</p>
</body></html>`;
}

const server = http.createServer((req, res) => {
  const requested = decodeURIComponent((req.url || '/').split('?')[0]);

  if (requested === '/' || requested === '/index.html') {
    const body = landingPage();
    res.writeHead(200, {
      'content-type': 'text/html; charset=utf-8',
      'content-length': Buffer.byteLength(body),
      'cache-control': 'no-store',
    });
    res.end(body);
    return;
  }

  // path.basename strips any directory component, so "../" segments are
  // discarded before the allowlist check even sees them.
  const name = path.basename(requested);
  const file = allowed.has(name) ? path.join(ROOT, name) : null;

  if (!file || !fs.existsSync(file)) {
    res.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' });
    res.end('Not found. Visit / for the list of available builds.\n');
    return;
  }

  const stat = fs.statSync(file);
  res.writeHead(200, {
    'content-type': MIME[path.extname(file)] || 'application/octet-stream',
    'content-length': stat.size,
    // Installers dislike a cached APK, and this is a one-shot download.
    'cache-control': 'no-store',
  });
  if (req.method === 'HEAD') {
    res.end();
    return;
  }
  fs.createReadStream(file).pipe(res);
});

server.listen(PORT, '0.0.0.0', () => {
  const lan = Object.values(os.networkInterfaces())
    .flat()
    .filter((n) => n && n.family === 'IPv4' && !n.internal)
    .map((n) => n.address);

  console.log('SecureChat downloads are being served from dist/');
  for (const ip of lan) {
    console.log(`\n  Open on your phone:  http://${ip}:${PORT}/`);
    console.log(`  Universal APK:      http://${ip}:${PORT}/${apks[0]}`);
  }
  console.log(`\n  Builds available: ${apks.join(', ')}`);
  console.log('\nPress Ctrl+C to stop.');
});

