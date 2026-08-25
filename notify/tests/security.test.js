const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');

process.env.SERVICE_KEY = 'test-service-key-that-is-at-least-32-bytes-long';
delete process.env.WEBHOOK_HOST_ALLOWLIST;
delete process.env.ALLOW_INSECURE_WEBHOOKS;

const { DeliveryError, dispatch, sendJson } = require('../src/dispatcher');
const {
  WebhookUrlError,
  createPinnedLookup,
  isPublicIp,
  resolveAndValidateWebhookUrl,
} = require('../src/url-security');

test('IP policy blocks non-public IPv4 and IPv6 address classes', () => {
  const blocked = [
    '0.0.0.0',
    '10.0.0.1',
    '100.64.0.1',
    '127.0.0.1',
    '169.254.169.254',
    '172.16.0.1',
    '192.168.0.1',
    '198.18.0.1',
    '224.0.0.1',
    '::',
    '::1',
    '::ffff:127.0.0.1',
    'fc00::1',
    'fe80::1',
    '2001:db8::1',
    '2002:7f00:1::',
  ];
  for (const address of blocked) assert.equal(isPublicIp(address), false, address);

  assert.equal(isPublicIp('1.1.1.1'), true);
  assert.equal(isPublicIp('2606:4700:4700::1111'), true);
});

test('hostname validation rejects any DNS answer that crosses a private boundary', async () => {
  const mixedLookup = async () => [
    { address: '1.1.1.1', family: 4 },
    { address: '10.0.0.7', family: 4 },
  ];

  await assert.rejects(
    resolveAndValidateWebhookUrl('https://hooks.example.com/event', { lookup: mixedLookup }),
    error => error instanceof WebhookUrlError && error.code === 'UNSAFE_WEBHOOK_URL'
  );
});

test('hostname validation returns only prevalidated public DNS answers', async () => {
  let lookupOptions;
  const target = await resolveAndValidateWebhookUrl('https://hooks.example.com/event?source=test', {
    lookup: async (hostname, options) => {
      assert.equal(hostname, 'hooks.example.com');
      lookupOptions = options;
      return [
        { address: '1.1.1.1', family: 4 },
        { address: '2606:4700:4700::1111', family: 6 },
      ];
    },
  });

  assert.deepEqual(lookupOptions, { all: true, verbatim: true });
  assert.equal(target.hostname, 'hooks.example.com');
  assert.deepEqual(target.addresses, [
    { address: '1.1.1.1', family: 4 },
    { address: '2606:4700:4700::1111', family: 6 },
  ]);
});

test('hostname allowlist is exact and cannot be bypassed with a suffix', async () => {
  const lookup = async () => [{ address: '1.1.1.1', family: 4 }];
  await resolveAndValidateWebhookUrl('https://hooks.example.com/event', {
    lookup,
    hostAllowlist: ['hooks.example.com'],
  });
  await assert.rejects(
    resolveAndValidateWebhookUrl('https://hooks.example.com.attacker.test/event', {
      lookup,
      hostAllowlist: ['hooks.example.com'],
    }),
    WebhookUrlError
  );
});

test('pinned lookup refuses a different hostname and returns only validated addresses', async () => {
  const lookup = createPinnedLookup('hooks.example.com', [{ address: '1.1.1.1', family: 4 }]);

  const address = await new Promise((resolve, reject) => {
    lookup('hooks.example.com', { family: 4 }, (error, resolved, family) => {
      if (error) return reject(error);
      return resolve({ resolved, family });
    });
  });
  assert.deepEqual(address, { resolved: '1.1.1.1', family: 4 });

  await assert.rejects(new Promise((resolve, reject) => {
    lookup('changed.example.com', {}, error => (error ? reject(error) : resolve()));
  }), error => error.code === 'EACCES');
});

test('dispatcher revalidates stored destinations immediately before delivery', async () => {
  let delivered = false;
  const result = await dispatch(
    { id: 'webhook-1', url: 'https://rebound.example.com/hook' },
    { event: 'scan.created' },
    {
      resolveTarget: async () => {
        throw new WebhookUrlError('DNS now resolves privately');
      },
      deliver: async () => {
        delivered = true;
      },
    }
  );

  assert.equal(delivered, false);
  assert.deepEqual(result, {
    webhookId: 'webhook-1',
    success: false,
    error: 'Webhook destination is not allowed',
    attempt: 1,
  });
});

test('dispatcher does not retry permanent receiver errors', async () => {
  let attempts = 0;
  const result = await dispatch(
    { id: 'webhook-2', url: 'https://hooks.example.com/hook' },
    {},
    {
      resolveTarget: async () => ({ url: new URL('https://hooks.example.com/hook') }),
      deliver: async () => {
        attempts += 1;
        throw new DeliveryError('HTTP 400', false);
      },
    }
  );
  assert.equal(attempts, 1);
  assert.equal(result.success, false);
  assert.equal(result.error, 'Webhook delivery failed');
});

test('outbound delivery never forwards the internal service key', async () => {
  let receivedHeaders;
  let receivedBody;
  const receiver = http.createServer((request, response) => {
    receivedHeaders = request.headers;
    const chunks = [];
    request.on('data', chunk => chunks.push(chunk));
    request.on('end', () => {
      receivedBody = Buffer.concat(chunks).toString('utf8');
      response.writeHead(204);
      response.end();
    });
  });

  await new Promise(resolve => receiver.listen(0, '127.0.0.1', resolve));
  const port = receiver.address().port;
  try {
    const payload = JSON.stringify({ event: 'scan.created' });
    await sendJson({
      url: new URL(`http://127.0.0.1:${port}/hook`),
      hostname: '127.0.0.1',
      addresses: [{ address: '127.0.0.1', family: 4 }],
    }, payload);

    assert.equal(receivedBody, payload);
    assert.equal(receivedHeaders['x-service-key'], undefined);
  } finally {
    await new Promise(resolve => receiver.close(resolve));
  }
});
