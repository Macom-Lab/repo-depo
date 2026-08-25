const http = require('node:http');
const https = require('node:https');
const config = require('./config');
const {
  WebhookUrlError,
  createPinnedLookup,
  resolveAndValidateWebhookUrl,
} = require('./url-security');

class DeliveryError extends Error {
  constructor(message, retryable = true) {
    super(message);
    this.name = 'DeliveryError';
    this.retryable = retryable;
  }
}

function sendJson(target, serializedPayload) {
  const transport = target.url.protocol === 'https:' ? https : http;
  const headers = {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(serializedPayload),
    'User-Agent': 'VulnTracker-Notify/1.0',
  };

  return new Promise((resolve, reject) => {
    const request = transport.request({
      protocol: target.url.protocol,
      hostname: target.hostname,
      port: target.url.port || undefined,
      method: 'POST',
      path: `${target.url.pathname}${target.url.search}`,
      headers,
      lookup: createPinnedLookup(target.hostname, target.addresses),
      agent: false,
    }, response => {
      response.resume();
      response.once('end', () => {
        const statusCode = response.statusCode || 0;
        if (statusCode >= 200 && statusCode < 300) {
          resolve();
          return;
        }
        reject(new DeliveryError(
          `Webhook returned HTTP ${statusCode}`,
          statusCode === 429 || statusCode >= 500
        ));
      });
    });

    request.setTimeout(config.TIMEOUT_MS, () => {
      request.destroy(new DeliveryError('Webhook request timed out'));
    });
    request.once('error', reject);
    request.end(serializedPayload);
  });
}

async function dispatch(webhook, payload, dependencies = {}) {
  const resolveTarget = dependencies.resolveTarget || resolveAndValidateWebhookUrl;
  const deliver = dependencies.deliver || sendJson;
  const serializedPayload = JSON.stringify(payload);

  for (let attempt = 1; attempt <= config.RETRY_ATTEMPTS; attempt++) {
    try {
      // Re-resolve immediately before every connection. The returned lookup is
      // pinned to the validated addresses, closing the DNS-rebinding window.
      const target = await resolveTarget(webhook.url);
      await deliver(target, serializedPayload);
      return { webhookId: webhook.id, success: true, attempt };
    } catch (err) {
      const retryable = !(err instanceof WebhookUrlError)
        && (!(err instanceof DeliveryError) || err.retryable);
      if (!retryable || attempt === config.RETRY_ATTEMPTS) {
        return {
          webhookId: webhook.id,
          success: false,
          error: err instanceof WebhookUrlError
            ? 'Webhook destination is not allowed'
            : 'Webhook delivery failed',
          attempt,
        };
      }
    }
  }
}

module.exports = { DeliveryError, dispatch, sendJson };
