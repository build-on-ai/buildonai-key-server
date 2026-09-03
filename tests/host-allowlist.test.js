#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-only
// Test allowlisty naglowka Host. Uruchomienie: node key-server/tests/host-allowlist.test.js
//
// Powod istnienia: bez tej kontroli strona w przegladarce moze uderzyc w key-server
// przez nazwe rozwiazujaca sie na loopback (DNS rebinding). Druga polowa testu pilnuje,
// zeby lista w kodzie i w docker-compose.yml nie rozjechaly sie po cichu: domyslna lista
// NIE zawiera key-server:3040, wiec sama zmiana w kodzie odcielaby uslugi w sieci Dockera.
const fs = require('fs');
const path = require('path');

const KS = path.join(__dirname, '..');
const src = fs.readFileSync(path.join(KS, 'server.js'), 'utf8');

function zbuduj(envValue, port) {
  const PORT = port;
  const process = { env: envValue === null ? {} : { KEY_SERVER_ALLOWED_HOSTS: envValue } };
  const m = src.match(/const ALLOWED_HOSTS = [\s\S]*?\n}\n/);
  if (!m) { console.error('nie znaleziono ALLOWED_HOSTS/isHostAllowed w server.js'); global.process.exit(1); }
  return eval(`${m[0]}; ({ ALLOWED_HOSTS, isHostAllowed })`);
}

let failed = 0;
function sprawdz(warunek, opis) {
  if (!warunek) { failed++; console.error(`FAIL ${opis}`); }
}

// --- lista z compose: co ma przejsc, co ma dostac 403 ---
const Z_COMPOSE = 'key-server:3040,localhost:3040,127.0.0.1:3040,[::1]:3040,'
  + 'localhost:13040,127.0.0.1:13040,[::1]:13040';
const { isHostAllowed } = zbuduj(Z_COMPOSE, 3040);

for (const host of ['key-server:3040', '127.0.0.1:13040', 'localhost:3040', '[::1]:13040']) {
  sprawdz(isHostAllowed(host) === true, `dozwolony host odrzucony: ${host}`);
}
for (const host of ['zly.example.com', 'key-server:9999', 'localhost', '', undefined, null, '127.0.0.1']) {
  sprawdz(isHostAllowed(host) === false, `niedozwolony host przepuszczony: ${JSON.stringify(host)}`);
}

// --- domyslna lista bez zmiennej: loopback tak, siec Dockera nie ---
const domyslna = zbuduj(null, 3040);
sprawdz(domyslna.isHostAllowed('127.0.0.1:3040') === true, 'domyslna lista odrzuca loopback');
sprawdz(domyslna.isHostAllowed('key-server:3040') === false,
  'domyslna lista dopuszcza key-server:3040 — wtedy wpis w compose bylby zbedny');

// --- kod i compose musza wymieniac te same hosty ---
const compose = fs.readFileSync(path.join(KS, 'docker-compose.yml'), 'utf8');
const wiersz = compose.split('\n').find((l) => l.includes('KEY_SERVER_ALLOWED_HOSTS'));
sprawdz(Boolean(wiersz), 'docker-compose.yml nie ustawia KEY_SERVER_ALLOWED_HOSTS');
if (wiersz) {
  for (const host of ['key-server:3040', '127.0.0.1:3040', '[::1]:3040']) {
    sprawdz(wiersz.includes(host), `compose nie dopuszcza: ${host}`);
  }
}

const razem = 4 + 7 + 2 + 1 + 3;
if (failed) { console.error(`\n${failed}/${razem} przypadkow nie przeszlo`); process.exit(1); }
console.log(`ok - ${razem}/${razem} przypadkow allowlisty Host`);
