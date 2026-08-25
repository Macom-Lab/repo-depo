const express = require('express');
const { randomUUID } = require('node:crypto');
const { authenticateService } = require('./authentication');
const { dispatch } = require('./dispatcher');
const { WebhookUrlError, resolveAndValidateWebhookUrl } = require('./url-security');
const config = require('./config');

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '64kb', strict: true }));

// In-memory webhook registry
const webhooks = new Map();

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function validEvents(events) {
  return Array.isArray(events)
    && events.length > 0
    && events.length <= config.ALLOWED_EVENTS.length
    && events.every(event => config.ALLOWED_EVENTS.includes(event));
}

// Health remains public for orchestrator probes. All state-changing and
// state-reading service operations require the internal service credential.
app.use('/webhooks', authenticateService);
app.use('/notify', authenticateService);

// Register a webhook endpoint to receive VulnTracker events
app.post('/webhooks', async (req, res, next) => {
  try {
    if (!isObject(req.body)) {
      return res.status(400).json({ error: 'request body must be a JSON object' });
    }
    const { url, events, metadata } = req.body;

    if (!url) return res.status(400).json({ error: 'url is required' });
    if (!validEvents(events)) {
      return res.status(400).json({
        error: `events must be a non-empty array containing only: ${config.ALLOWED_EVENTS.join(', ')}`,
      });
    }
    if (metadata !== undefined && !isObject(metadata)) {
      return res.status(400).json({ error: 'metadata must be a JSON object' });
    }
    if (webhooks.size >= config.MAX_WEBHOOKS) {
      return res.status(503).json({ error: 'webhook registration capacity reached' });
    }

    const target = await resolveAndValidateWebhookUrl(url);
    const webhook = {
      id: randomUUID(),
      url: target.url.href,
      events: [...new Set(events)],
      metadata: metadata === undefined ? {} : Object.fromEntries(Object.entries(metadata)),
      createdAt: new Date().toISOString(),
    };

    webhooks.set(webhook.id, webhook);
    return res.status(201).json(webhook);
  } catch (err) {
    if (err instanceof WebhookUrlError) {
      return res.status(400).json({ error: 'url is not an allowed webhook destination' });
    }
    return next(err);
  }
});


// List all registered webhooks
app.get('/webhooks', (req, res) => {
  res.json({ webhooks: Array.from(webhooks.values()), count: webhooks.size });
});


// Delete a webhook registration
app.delete('/webhooks/:id', (req, res) => {
  if (!webhooks.has(req.params.id)) {
    return res.status(404).json({ error: 'Webhook not found' });
  }
  webhooks.delete(req.params.id);
  res.status(204).send();
});


// Trigger event notifications — called by the Python API on scan create/update
// Assumed to be reachable only from internal network; no authentication applied
app.post('/notify', async (req, res) => {
  if (!isObject(req.body)) {
    return res.status(400).json({ error: 'request body must be a JSON object' });
  }
  const { event, payload } = req.body;

  if (!config.ALLOWED_EVENTS.includes(event) || !isObject(payload)) {
    return res.status(400).json({ error: 'event and payload are required' });
  }

  const matching = Array.from(webhooks.values()).filter(w => w.events.includes(event));

  const results = await Promise.all(
    matching.map(w => dispatch(w, { event, payload, timestamp: new Date().toISOString() }))
  );

  res.json({ event, dispatched: matching.length, results });
});


// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'vulntracker-notify' });
});


// Global error handler
app.use((err, req, res, next) => {
  console.error(err);
  if (err.type === 'entity.too.large') {
    return res.status(413).json({ error: 'Request body is too large' });
  }
  if (err instanceof SyntaxError && err.status === 400) {
    return res.status(400).json({ error: 'Malformed JSON request body' });
  }
  return res.status(500).json({ error: 'Internal server error' });
});


if (require.main === module) {
  app.listen(config.PORT, () => {
    console.log(`Notification service running on http://localhost:${config.PORT}`);
  });
}

module.exports = app;
