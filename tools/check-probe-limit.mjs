// Verifies the "is this number registered?" typing aid cannot exhaust the
// password-attempt budget. Before the fix both shared one 10-requests-per-minute
// bucket, so editing a phone number a few times locked the user out of sign-in
// before they had submitted anything.
const BASE = process.argv[2] || 'http://127.0.0.1:4000';
const PHONE = '+15550007777';

const probes = [];
for (let i = 0; i < 120; i += 1) {
  probes.push(fetch(`${BASE}/api/auth/check/${encodeURIComponent(PHONE)}`));
}

let ok = 0;
let limited = 0;
for (const res of await Promise.all(probes)) {
  if (res.status === 200) ok += 1;
  else if (res.status === 429) limited += 1;
}

const login = await fetch(`${BASE}/api/auth/login`, {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ phone: PHONE, password: 'wrong-password-1' }),
});
const body = await login.json().catch(() => ({}));

console.log(`probes: ${ok} served, ${limited} limited`);
console.log(`login after 120 probes: ${login.status} ${body.code || body.error || ''}`);
console.log(
  login.status === 429
    ? 'FAIL  the typing aid still steals the password budget'
    : 'PASS  sign-in is unaffected by lookups',
);
