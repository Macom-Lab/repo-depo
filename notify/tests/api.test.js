const test = require('node:test');
const assert = require('node:assert/strict');

process.env.SERVICE_KEY = 'test-service-key-that-is-at-least-32-bytes-long';
delete process.env.WEBHOOK_HOST_ALLOWLIST;
delete process.env.ALLOW_INSECURE_WEBHOOKS;

const app = require('../src/index');

const SERVICE_KEY = process.env.SERVICE_KEY;
let baseUrl;
let server;

test.before(async () => {
  await new Promise(resolve => {
    server = app.listen(0, '127.0.0.1', resolve);
  });
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

test.after(async () => {
  await new Promise(resolve => server.close(resolve));
});

async function request(path, { method = 'GET', body, authenticated = true, headers = {} } = {}) {
  const requestHeaders = { ...headers };
  if (authenticated) requestHeaders['X-Service-Key'] = SERVICE_KEY;
  if (body !== undefined) requestHeaders['Content-Type'] = 'application/json';

  const response = await fetch(`${baseUrl}${path}`, {
    method,
    headers: requestHeaders,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await response.text();
  return {
    status: response.status,
    body: text ? JSON.parse(text) : undefined,
    headers: response.headers,
  };
}

test('GET /health remains public and omits the Express fingerprint', async () => {
  const { status, body, headers } = await request('/health', { authenticated: false });
  assert.equal(status, 200);
  assert.equal(body.status, 'ok');
  assert.equal(headers.get('x-powered-by'), null);
});

test('sensitive endpoints reject missing or invalid service credentials', async () => {
  const attempts = [
    request('/webhooks', { authenticated: false }),
    request('/webhooks', {
      method: 'POST',
      body: { url: 'https://1.1.1.1/hook', events: ['scan.created'] },
      authenticated: false,
    }),
    request('/webhooks/not-present', { method: 'DELETE', authenticated: false }),
    request('/notify', {
      method: 'POST',
      body: { event: 'scan.created', payload: {} },
      authenticated: false,
    }),
    request('/notify', {
      method: 'POST',
      body: { event: 'scan.created', payload: {} },
      headers: { 'X-Service-Key': 'wrong-key' },
      authenticated: false,
    }),
  ];

  const responses = await Promise.all(attempts);
  assert.deepEqual(responses.map(response => response.status), [401, 401, 401, 401, 401]);
  assert.ok(responses.every(response => response.body.error === 'Unauthorized'));
});

test('POST /webhooks registers a public HTTPS webhook when authenticated', async () => {
  const { status, body } = await request('/webhooks', {
    method: 'POST',
    body: {
      url: 'https://1.1.1.1/hook',
      events: ['scan.created'],
      metadata: { owner: 'security' },
    },
  });
  assert.equal(status, 201);
  assert.ok(body.id);
  assert.equal(body.url, 'https://1.1.1.1/hook');
  assert.deepEqual(body.metadata, { owner: 'security' });
});

test('POST /webhooks rejects invalid registration bodies', async () => {
  const missingUrl = await request('/webhooks', {
    method: 'POST',
    body: { events: ['scan.created'] },
  });
  const emptyEvents = await request('/webhooks', {
    method: 'POST',
    body: { url: 'https://1.1.1.1', events: [] },
  });
  const unknownEvent = await request('/webhooks', {
    method: 'POST',
    body: { url: 'https://1.1.1.1', events: ['admin.created'] },
  });
  const invalidMetadata = await request('/webhooks', {
    method: 'POST',
    body: { url: 'https://1.1.1.1', events: ['scan.created'], metadata: [] },
  });

  assert.deepEqual(
    [missingUrl.status, emptyEvents.status, unknownEvent.status, invalidMetadata.status],
    [400, 400, 400, 400]
  );
});

test('POST /webhooks blocks private, local, credentialed, and plaintext destinations', async () => {
  const urls = [
    'https://127.0.0.1/hook',
    'https://169.254.169.254/latest/meta-data',
    'https://[::1]/hook',
    'https://localhost/hook',
    'https://user:password@1.1.1.1/hook',
    'http://1.1.1.1/hook',
  ];

  for (const url of urls) {
    const { status, body } = await request('/webhooks', {
      method: 'POST',
      body: { url, events: ['scan.created'] },
    });
    assert.equal(status, 400, url);
    assert.equal(body.error, 'url is not an allowed webhook destination');
  }
});

test('GET /webhooks lists registrations only when authenticated', async () => {
  const { status, body } = await request('/webhooks');
  assert.equal(status, 200);
  assert.ok(Array.isArray(body.webhooks));
  assert.equal(body.count, body.webhooks.length);
});

test('DELETE /webhooks/:id removes a webhook only when authenticated', async () => {
  const registration = await request('/webhooks', {
    method: 'POST',
    body: {
      url: 'https://8.8.8.8/deleteme',
      events: ['scan.updated'],
    },
  });
  assert.equal(registration.status, 201);

  const deletion = await request(`/webhooks/${registration.body.id}`, { method: 'DELETE' });
  assert.equal(deletion.status, 204);

  const missing = await request('/webhooks/non-existent-id', { method: 'DELETE' });
  assert.equal(missing.status, 404);
});

test('POST /notify validates the event and payload after authentication', async () => {
  const missingPayload = await request('/notify', {
    method: 'POST',
    body: { event: 'scan.created' },
  });
  const unknownEvent = await request('/notify', {
    method: 'POST',
    body: { event: 'arbitrary.event', payload: {} },
  });
  assert.equal(missingPayload.status, 400);
  assert.equal(unknownEvent.status, 400);
});
