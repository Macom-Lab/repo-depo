function positiveInteger(name, fallback) {
  const rawValue = process.env[name];
  if (rawValue === undefined) return fallback;

  const value = Number(rawValue);
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`${name} must be a positive integer`);
  }
  return value;
}

function boolean(name, fallback = false) {
  const rawValue = process.env[name];
  if (rawValue === undefined) return fallback;
  if (rawValue === 'true') return true;
  if (rawValue === 'false') return false;
  throw new Error(`${name} must be either "true" or "false"`);
}

function serviceKey() {
  const value = process.env.SERVICE_KEY;
  if (!value || Buffer.byteLength(value, 'utf8') < 32) {
    throw new Error('SERVICE_KEY must be set to a secret containing at least 32 bytes');
  }
  return value;
}

const allowInsecureWebhooks = boolean('ALLOW_INSECURE_WEBHOOKS');
const defaultPorts = allowInsecureWebhooks ? ['443', '80'] : ['443'];
const allowedPorts = (process.env.WEBHOOK_ALLOWED_PORTS || defaultPorts.join(','))
  .split(',')
  .map(port => port.trim())
  .filter(Boolean);

if (allowedPorts.length === 0 || allowedPorts.some(port => !/^\d{1,5}$/.test(port) || Number(port) > 65535)) {
  throw new Error('WEBHOOK_ALLOWED_PORTS must be a comma-separated list of valid ports');
}

module.exports = Object.freeze({
  PORT: positiveInteger('PORT', 3001),
  SERVICE_KEY: serviceKey(),
  RETRY_ATTEMPTS: positiveInteger('RETRY_ATTEMPTS', 3),
  TIMEOUT_MS: positiveInteger('TIMEOUT_MS', 5000),
  DNS_TIMEOUT_MS: positiveInteger('DNS_TIMEOUT_MS', 2000),
  MAX_WEBHOOKS: positiveInteger('MAX_WEBHOOKS', 1000),
  ALLOW_INSECURE_WEBHOOKS: allowInsecureWebhooks,
  WEBHOOK_ALLOWED_PORTS: Object.freeze(allowedPorts),
  WEBHOOK_HOST_ALLOWLIST: Object.freeze(
    (process.env.WEBHOOK_HOST_ALLOWLIST || '')
      .split(',')
      .map(host => host.trim().toLowerCase().replace(/\.$/, ''))
      .filter(Boolean)
  ),
  ALLOWED_EVENTS: Object.freeze(['scan.created', 'scan.updated']),
});
