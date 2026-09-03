#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-only
// Test dopasowania adresu w isIpAllowed. Uruchomienie: node key-server/tests/cidr.test.js
//
// Powod istnienia: implementacja sprzed poprawki porownywala staly trzeci oktet,
// wiec KAZDY zakres inny niz /24 byl niedopasowywalny - w tym trzy zakresy /16
// z dostarczonego allowed-clients.json.example. Zawodzila ZAMKNIETO (odrzucala
// uprawnionych), wiec nie bylo to obejscie kontroli, tylko cicha awaria dostepu.
const fs = require('fs');
const path = require('path');
const net = require('net');

const src = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');
for (const re of [/function isIpAllowed[\s\S]*?\n}\n/, /function inCidr[\s\S]*?\n}\n/]) {
  const m = src.match(re);
  if (!m) { console.error(`nie znaleziono ${re} w server.js`); process.exit(1); }
  eval(m[0]);
}

const CASES = [
  ['172.19.5.7',      ['172.19.0.0/16'], true,  '/16 z dostarczonego przykladu'],
  ['172.19.255.254',  ['172.19.0.0/16'], true,  'gorna granica /16'],
  ['172.20.0.1',      ['172.19.0.0/16'], false, 'sasiedni /16 odrzucony'],
  ['10.0.0.9',        ['10.0.0.0/24'],   true,  'zwykly /24'],
  ['10.0.1.5',        ['10.0.0.0/24'],   false, 'inny /24'],
  ['10.0.0.9',        ['10.0.0.0/8'],    true,  'szeroki /8'],
  ['192.0.2.1',       ['10.0.0.0/8'],    false, 'poza /8'],
  ['not-an-ip',       ['10.0.0.0/24'],   false, 'wejscie nie bedace adresem'],
  ['10.0.0.9',        ['10.0.0.0/bad'],  false, 'zepsuta maska'],
  ['10.0.0.9',        ['10.0.0.0/99'],   false, 'maska poza zakresem'],
  ['127.0.0.1',       [],                true,  'loopback zawsze dozwolony'],
  ['::1',             [],                true,  'loopback IPv6 zawsze dozwolony'],
  ['192.0.2.7',       ['192.0.2.7'],     true,  'dokladny adres'],
  ['192.0.2.8',       ['192.0.2.7'],     false, 'dokladny adres to nie prefiks'],
  ['2001:db8::5',     ['2001:db8::/32'], true,  'prefiks IPv6'],
  ['2001:db9::5',     ['2001:db8::/32'], false, 'poza prefiksem IPv6'],
  ['2001:db8::5',     ['10.0.0.0/8'],    false, 'klient IPv6 kontra zakres IPv4'],
  ['10.0.0.9',        ['2001:db8::/32'], false, 'klient IPv4 kontra zakres IPv6'],
  // Docker podaje adres jako IPv4-mapped, gdy serwer nasluchuje na ::
  ['::ffff:172.19.5.7', ['172.19.0.0/16'], true,  'IPv4-mapped w zakresie IPv4'],
  ['::ffff:172.20.0.1', ['172.19.0.0/16'], false, 'IPv4-mapped poza zakresem'],
];

let failed = 0;
for (const [ip, ranges, expected, why] of CASES) {
  const got = isIpAllowed(ip, ranges);
  if (got !== expected) {
    failed++;
    console.error(`FAIL ${ip} w [${ranges}] -> ${got}, oczekiwano ${expected} (${why})`);
  }
}
if (failed) { console.error(`\n${failed}/${CASES.length} przypadkow nie przeszlo`); process.exit(1); }
console.log(`ok - ${CASES.length}/${CASES.length} przypadkow allowlisty adresow`);
