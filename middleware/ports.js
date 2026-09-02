
'use strict';

const fs = require('fs');
const path = require('path');

let _cache = null;

function _findPortsFile() {
  if (process.env.CS_PORTS_FILE) return process.env.CS_PORTS_FILE;
  let dir = __dirname;
  for (let i = 0; i < 6; i++) {
    const candidate = path.join(dir, 'ports.yaml');
    if (fs.existsSync(candidate)) return candidate;
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return null;
}

function _loadPorts() {
  if (_cache !== null) return _cache;
  const file = _findPortsFile();
  if (!file) {
    _cache = {};
    return _cache;
  }
  let text;
  try {
    text = fs.readFileSync(file, 'utf8');
  } catch (_e) {
    _cache = {};
    return _cache;
  }
  const out = {};
  let inPorts = false;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/#.*$/, '');
    const trimmed = line.trim();
    if (!trimmed) continue;
    if (/^[A-Za-z][\w-]*\s*:\s*$/.test(trimmed)) {
      inPorts = trimmed.replace(/\s*:\s*$/, '') === 'ports';
      continue;
    }
    if (inPorts) {
      const m = trimmed.match(/^([A-Za-z][\w-]*)\s*:\s*(\d+)\b/);
      if (m) out[m[1]] = parseInt(m[2], 10);
    }
  }
  _cache = out;
  return _cache;
}

function getPort(serviceName, fallback) {
  const envSpecific = process.env[`PORT_${serviceName.toUpperCase().replace(/-/g, '_')}`];
  if (envSpecific) {
    const n = parseInt(envSpecific, 10);
    if (Number.isFinite(n)) return n;
  }
  if (process.env.PORT && process.env._CS_PORT_OWNER === serviceName) {
    const n = parseInt(process.env.PORT, 10);
    if (Number.isFinite(n)) return n;
  }
  const cfg = _loadPorts();
  if (cfg[serviceName] != null) return cfg[serviceName];
  if (fallback != null) return fallback;
  throw new Error(`ports: no entry for '${serviceName}' (no PORT_${serviceName.toUpperCase()} env, no ports.yaml entry, no fallback)`);
}

function ownPort(serviceName, fallback) {
  if (process.env.PORT) {
    const n = parseInt(process.env.PORT, 10);
    if (Number.isFinite(n)) return n;
  }
  return getPort(serviceName, fallback);
}

module.exports = { getPort, ownPort, _loadPorts };
