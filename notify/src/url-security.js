const dns = require('node:dns').promises;
const net = require('node:net');
const config = require('./config');

class WebhookUrlError extends Error {
  constructor(message) {
    super(message);
    this.name = 'WebhookUrlError';
    this.code = 'UNSAFE_WEBHOOK_URL';
  }
}

function parseIpv4(address) {
  if (net.isIP(address) !== 4) return null;
  return address.split('.').map(part => Number(part));
}

function parseIpv6(address) {
  let value = address.toLowerCase().split('%', 1)[0];
  if (net.isIP(value) !== 6) return null;

  const ipv4Match = value.match(/(\d+\.\d+\.\d+\.\d+)$/);
  if (ipv4Match) {
    const ipv4 = parseIpv4(ipv4Match[1]);
    if (!ipv4) return null;
    value = value.slice(0, -ipv4Match[1].length)
      + `${((ipv4[0] << 8) | ipv4[1]).toString(16)}:${((ipv4[2] << 8) | ipv4[3]).toString(16)}`;
  }

  const halves = value.split('::');
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const missing = 8 - left.length - right.length;
  if ((halves.length === 1 && missing !== 0) || missing < 0) return null;

  const groups = [...left, ...Array(missing).fill('0'), ...right]
    .map(group => Number.parseInt(group || '0', 16));
  if (groups.length !== 8 || groups.some(group => !Number.isInteger(group) || group < 0 || group > 0xffff)) {
    return null;
  }

  return groups.flatMap(group => [group >> 8, group & 0xff]);
}

function isPublicIpv4(address) {
  const octets = parseIpv4(address);
  if (!octets) return false;
  const [a, b, c] = octets;

  return !(
    a === 0
    || a === 10
    || a === 127
    || (a === 100 && b >= 64 && b <= 127)
    || (a === 169 && b === 254)
    || (a === 172 && b >= 16 && b <= 31)
    || (a === 192 && b === 0 && c === 0)
    || (a === 192 && b === 0 && c === 2)
    || (a === 192 && b === 168)
    || (a === 198 && (b === 18 || b === 19))
    || (a === 198 && b === 51 && c === 100)
    || (a === 203 && b === 0 && c === 113)
    || a >= 224
  );
}

function isPublicIpv6(address) {
  const bytes = parseIpv6(address);
  if (!bytes) return false;

  // IPv4-mapped IPv6 addresses must be evaluated using the IPv4 policy.
  if (bytes.slice(0, 10).every(byte => byte === 0) && bytes[10] === 0xff && bytes[11] === 0xff) {
    return isPublicIpv4(bytes.slice(12).join('.'));
  }

  // Only globally routable unicast space is accepted. Explicitly exclude
  // documentation, tunnelling, benchmarking, and ORCHID ranges within it.
  if ((bytes[0] & 0xe0) !== 0x20) return false; // outside 2000::/3
  if (bytes[0] === 0x20 && bytes[1] === 0x01) {
    if (bytes[2] === 0x00 && bytes[3] === 0x00) return false; // Teredo
    if (bytes[2] === 0x00 && bytes[3] === 0x02) return false; // benchmarking
    if (bytes[2] === 0x00 && (bytes[3] & 0xf0) === 0x10) return false; // ORCHID
    if (bytes[2] === 0x00 && (bytes[3] & 0xf0) === 0x20) return false; // ORCHIDv2
    if (bytes[2] === 0x0d && bytes[3] === 0xb8) return false; // documentation
  }
  if (bytes[0] === 0x20 && bytes[1] === 0x02) return false; // 6to4
  return true;
}

function isPublicIp(address) {
  const version = net.isIP(address);
  if (version === 4) return isPublicIpv4(address);
  if (version === 6) return isPublicIpv6(address);
  return false;
}

function normalizedHostname(hostname) {
  return hostname.toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
}

function withTimeout(promise, timeoutMs) {
  let timer;
  const timeout = new Promise((resolve, reject) => {
    timer = setTimeout(() => reject(new Error('DNS resolution timed out')), timeoutMs);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

async function resolveAndValidateWebhookUrl(rawUrl, options = {}) {
  const lookup = options.lookup || dns.lookup;
  const allowHttp = options.allowHttp ?? config.ALLOW_INSECURE_WEBHOOKS;
  const allowedPorts = options.allowedPorts || config.WEBHOOK_ALLOWED_PORTS;
  const hostAllowlist = options.hostAllowlist || config.WEBHOOK_HOST_ALLOWLIST;
  const timeoutMs = options.timeoutMs || config.DNS_TIMEOUT_MS;

  if (typeof rawUrl !== 'string' || rawUrl.length === 0 || rawUrl.length > 2048) {
    throw new WebhookUrlError('Webhook URL must be a non-empty string of at most 2048 characters');
  }

  let url;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new WebhookUrlError('Webhook URL is invalid');
  }

  const allowedProtocols = allowHttp ? ['https:', 'http:'] : ['https:'];
  if (!allowedProtocols.includes(url.protocol)) {
    throw new WebhookUrlError('Webhook URL must use HTTPS');
  }
  if (url.username || url.password) {
    throw new WebhookUrlError('Webhook URL must not contain credentials');
  }
  if (url.hash) {
    throw new WebhookUrlError('Webhook URL must not contain a fragment');
  }

  const hostname = normalizedHostname(url.hostname);
  if (!hostname || hostname === 'localhost' || hostname.endsWith('.localhost')) {
    throw new WebhookUrlError('Webhook hostname is not allowed');
  }
  if (hostAllowlist.length > 0 && !hostAllowlist.includes(hostname)) {
    throw new WebhookUrlError('Webhook hostname is not in the configured allowlist');
  }

  const effectivePort = url.port || (url.protocol === 'https:' ? '443' : '80');
  if (!allowedPorts.includes(effectivePort)) {
    throw new WebhookUrlError('Webhook port is not allowed');
  }

  let addresses;
  const literalVersion = net.isIP(hostname);
  if (literalVersion) {
    addresses = [{ address: hostname, family: literalVersion }];
  } else {
    try {
      addresses = await withTimeout(
        Promise.resolve(lookup(hostname, { all: true, verbatim: true })),
        timeoutMs
      );
    } catch {
      throw new WebhookUrlError('Webhook hostname could not be safely resolved');
    }
  }

  if (!Array.isArray(addresses) || addresses.length === 0) {
    throw new WebhookUrlError('Webhook hostname did not resolve to an address');
  }

  const normalizedAddresses = addresses.map(({ address, family }) => ({
    address,
    family: Number(family) || net.isIP(address),
  }));
  if (normalizedAddresses.some(({ address, family }) => ![4, 6].includes(family) || !isPublicIp(address))) {
    throw new WebhookUrlError('Webhook hostname resolves to a non-public address');
  }

  return Object.freeze({
    url,
    hostname,
    addresses: Object.freeze(normalizedAddresses.map(address => Object.freeze(address))),
  });
}

function createPinnedLookup(expectedHostname, addresses) {
  const expected = normalizedHostname(expectedHostname);
  let nextAddress = 0;

  return (requestedHostname, options, callback) => {
    let lookupOptions = options;
    let done = callback;
    if (typeof options === 'function') {
      done = options;
      lookupOptions = {};
    }

    if (normalizedHostname(requestedHostname) !== expected) {
      const error = new Error('Refused DNS lookup for unexpected webhook hostname');
      error.code = 'EACCES';
      return process.nextTick(done, error);
    }

    const requestedFamily = Number(lookupOptions && lookupOptions.family) || 0;
    const candidates = requestedFamily
      ? addresses.filter(item => item.family === requestedFamily)
      : addresses;
    if (candidates.length === 0) {
      const error = new Error('No validated address matches the requested address family');
      error.code = 'ENOTFOUND';
      return process.nextTick(done, error);
    }

    if (lookupOptions && lookupOptions.all) {
      return process.nextTick(done, null, candidates.map(item => ({ ...item })));
    }

    const selected = candidates[nextAddress % candidates.length];
    nextAddress += 1;
    return process.nextTick(done, null, selected.address, selected.family);
  };
}

module.exports = {
  WebhookUrlError,
  createPinnedLookup,
  isPublicIp,
  resolveAndValidateWebhookUrl,
};
