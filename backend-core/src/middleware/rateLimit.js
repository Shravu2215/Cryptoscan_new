'use strict';

const rateLimit = require('express-rate-limit');

function buildStore(prefix) {
  if (!process.env.REDIS_URL || process.env.REDIS_URL.includes('redis:6379')) return undefined;

  try {
    const Redis = require('ioredis');
    const { RedisStore } = require('rate-limit-redis');
    const client = new Redis(process.env.REDIS_URL, { lazyConnect: true, maxRetriesPerRequest: 1 });
    client.on('error', (err) => console.error('Rate-limit Redis error:', err.message));
    client.connect().catch(err => console.error('Rate-limit Redis connect failed:', err.message));
    return new RedisStore({ prefix: prefix || 'rl:', sendCommand: (...args) => client.call(...args) });
  } catch (err) {
    console.warn('Redis rate-limit store unavailable, falling back to in-memory:', err.message);
    return undefined;
  }
}

const isDev = process.env.NODE_ENV !== 'production' || !process.env.REDIS_URL;

// Generous ceiling for normal API traffic (uploads, scans, polling).
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 600,
  standardHeaders: true,
  legacyHeaders: false,
  store: buildStore('rl:api:'),
});

// Tight limit on credential-guessing surfaces.
const authLimiter = rateLimit({
  windowMs: isDev ? 5 * 60 * 1000 : 15 * 60 * 1000,
  limit: isDev ? 200 : 20,
  standardHeaders: true,
  legacyHeaders: false,
  store: buildStore('rl:auth:'),
  message: { error: 'Too many auth attempts, please try again later' },
});

module.exports = { apiLimiter, authLimiter };
