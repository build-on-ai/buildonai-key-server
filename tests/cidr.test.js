#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-only
const fs = require('fs');
const path = require('path');
const net = require('net');

const src = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');
const m = src.match(/function isIpAllowed[\s\S]*?\n}\n/);
if (!m) { console.error('isIpAllowed not found in server.js'); process.exit(1); }
eval(m[0]);

const CASES = [
  ['172.19.5.7',     ['172.19.0.0/16'], true,  'address inside a /16'],
  ['172.19.255.254', ['172.19.0.0/16'], true,  'top of the /16'],
  ['172.20.0.1',     ['172.19.0.0/16'], false, 'neighbouring /16 rejected'],
  ['10.0.0.9',       ['10.0.0.0/24'],   true,  'plain /24'],
  ['10.0.1.5',       ['10.0.0.0/24'],   false, 'different /24'],
  ['10.0.0.9',       ['10.0.0.0/8'],    true,  'wide /8'],
  ['192.0.2.1',      ['10.0.0.0/8'],    false, 'outside the /8'],
  ['not-an-ip',      ['10.0.0.0/24'],   false, 'non-address input rejected'],
  ['10.0.0.9',       ['10.0.0.0/bad'],  false, 'malformed mask rejected'],
  ['127.0.0.1',      [],                true,  'loopback always allowed'],
  ['::1',            [],                true,  'IPv6 loopback always allowed'],
  ['192.0.2.7',      ['192.0.2.7'],     true,  'exact address match'],
  ['192.0.2.8',      ['192.0.2.7'],     false, 'exact match is not a prefix'],
  ['2001:db8::5',    ['2001:db8::/32'], true,  'IPv6 prefix match'],
  ['2001:db9::5',    ['2001:db8::/32'], false, 'IPv6 outside the prefix'],
  ['2001:db8::5',    ['10.0.0.0/8'],    false, 'IPv6 client against IPv4 range'],
  ['10.0.0.9',       ['2001:db8::/32'], false, 'IPv4 client against IPv6 range'],
];

let failed = 0;
for (const [ip, ranges, expected, why] of CASES) {
  const got = isIpAllowed(ip, ranges);
  if (got !== expected) {
    failed++;
    console.error(`FAIL ${ip} in [${ranges}] -> ${got}, expected ${expected} (${why})`);
  }
}
if (failed) { console.error(`\n${failed}/${CASES.length} cases failed`); process.exit(1); }
console.log(`ok - ${CASES.length}/${CASES.length} address-allowlist cases`);
