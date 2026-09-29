// Verifies that the vendored Nearby Connections plugin really is inside the
// built APK, and that the offline-mesh UI strings are present.
//
// Raw byte scanning of a .apk is not enough: zip entries are DEFLATE-compressed,
// so a string inside classes.dex will not be found in the container bytes. This
// script extracts the dex files and searches those instead.
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

const apk = process.argv[2];
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'apk-verify-'));

// Expand-Archive only accepts .zip extensions, so copy with that suffix.
const zipCopy = path.join(tmp, 'app.zip');
fs.copyFileSync(apk, zipCopy);
execFileSync(
  'powershell',
  ['-NoProfile', '-Command', `Expand-Archive -LiteralPath '${zipCopy}' -DestinationPath '${tmp}\\x' -Force`],
  { stdio: 'ignore' },
);
const root = path.join(tmp, 'x');

const dexDir = path.join(root, 'classes.dex');
const dexFiles = fs.existsSync(dexDir)
  ? fs
      .readdirSync(root)
      .filter((f) => /^classes\d*\.dex$/.test(f))
  : [];

// The plugin's package path as it appears in a dex string table.
const pluginNeedle = 'nankai';
const pluginFiles = dexFiles.filter((f) =>
  fs.readFileSync(path.join(root, f)).includes(Buffer.from(pluginNeedle)),
);

console.log('APK            :', path.basename(apk));
console.log('dex files      :', dexFiles.length);
console.log('plugin dex     :', pluginFiles.length ? pluginFiles.join(', ') : 'NOT FOUND');

const libDir = path.join(root, 'lib');
const abis = fs.existsSync(libDir) ? fs.readdirSync(libDir) : [];
console.log('ABIs           :', abis.join(', '));

// The Dart AOT snapshot, which is NOT compressed, so a direct search is valid.
const libapp = abis.length
  ? path.join(root, 'lib', abis[0], 'libapp.so')
  : null;
if (libapp && fs.existsSync(libapp)) {
  const so = fs.readFileSync(libapp);
  // Add a check here for any fix that must be provably present in a release
  // Add a check here for any fix that must be provably present in a release
  // build, so 'it worked in debug' cannot hide an unshipped change.
  //
  // Encoding matters. The Dart AOT snapshot stores a string as UTF-8 when it is
  // pure ASCII, but as UTF-16 as soon as it contains a non-ASCII character. Most
  // user-facing strings here start with an emoji, so a UTF-8-only search reports
  // MISSING for code that is actually present. Check both encodings.
  const strings = [
    ['NearbyService', 'NearbyService'],
    ['NOT encrypted banner', 'NOT encrypted. Anyone in radio range'],
    ['readable by relays', 'readable by relays'],
    ['ghost_ name prefix', 'ghost_'],
    // Auth fix: a 401 must be reported, not silently swallowed.
    ['session-expired notice', 'Session expired. Please sign in again.'],
    ['handleUnauthorized', 'handleUnauthorized'],
    // Pre-key id fix: the vault carries the id it stored under, and a missing
    // pre-key is a named error instead of being silently dropped.
    ['MintedPreKeys', 'MintedPreKeys'],
    ['missing_prekey', 'missing_prekey'],
    ['new integrity copy', 'wrong key on this device'],
  ];
  for (const [label, needle] of strings) {
    const utf8 = so.includes(Buffer.from(needle, 'utf8'));
    const utf16 = so.includes(Buffer.from(needle, 'utf16le'));
    const how = utf8 ? 'PRESENT (utf8)' : utf16 ? 'PRESENT (utf16)' : 'MISSING';
    console.log(('  ' + label).padEnd(28), how);
  }
} else {
  console.log('libapp.so      : not found');
}

fs.rmSync(tmp, { recursive: true, force: true });
