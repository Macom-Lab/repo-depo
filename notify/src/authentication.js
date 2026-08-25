const crypto = require('node:crypto');
const config = require('./config');

function secretsMatch(candidate, expected) {
  if (typeof candidate !== 'string') return false;

  const candidateBuffer = Buffer.from(candidate, 'utf8');
  const expectedBuffer = Buffer.from(expected, 'utf8');
  return candidateBuffer.length === expectedBuffer.length
    && crypto.timingSafeEqual(candidateBuffer, expectedBuffer);
}

function authenticateService(req, res, next) {
  if (!secretsMatch(req.get('X-Service-Key'), config.SERVICE_KEY)) {
    res.set('WWW-Authenticate', 'ApiKey realm="vulntracker-notify"');
    return res.status(401).json({ error: 'Unauthorized' });
  }
  return next();
}

module.exports = { authenticateService, secretsMatch };
