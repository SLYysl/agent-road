import { createHash, randomBytes as cryptoRandomBytes, randomUUID } from 'node:crypto';

import { withFileLock } from '../storage/file-lock.mjs';
import { readJson, writeJsonAtomic } from '../storage/json-file.mjs';

function hashToken(token) {
  return createHash('sha256').update(token, 'utf8').digest('hex');
}

function parseCanonicalIso(value) {
  if (typeof value !== 'string') return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) || date.toISOString() !== value ? null : date;
}

function validateTokenStore(data) {
  if (data === null || typeof data !== 'object' || !Array.isArray(data.tokens)) {
    throw new Error('invalid enrollment token store');
  }

  for (const record of data.tokens) {
    if (
      record === null
      || typeof record !== 'object'
      || !/^enr_[a-f0-9]{32}$/.test(record.id)
      || typeof record.deviceId !== 'string'
      || !/^dev_[a-z0-9]+$/.test(record.deviceId)
      || typeof record.tokenHash !== 'string'
      || !/^[a-f0-9]{64}$/.test(record.tokenHash)
      || (record.consumedAt !== null && typeof record.consumedAt !== 'string')
    ) {
      throw new Error('invalid enrollment token store');
    }

    const issuedAt = parseCanonicalIso(record.issuedAt);
    const expiresAt = parseCanonicalIso(record.expiresAt);
    const consumedAt = record.consumedAt === null ? null : parseCanonicalIso(record.consumedAt);
    if (
      !issuedAt
      || !expiresAt
      || (record.consumedAt !== null && !consumedAt)
      || issuedAt >= expiresAt
      || (consumedAt && (consumedAt < issuedAt || consumedAt >= expiresAt))
    ) {
      throw new Error('invalid enrollment token store');
    }
  }
  return data;
}

export class EnrollmentTokenStore {
  constructor(path, { now = () => new Date(), randomBytes = cryptoRandomBytes } = {}) {
    this.path = path;
    this.now = now;
    this.randomBytes = randomBytes;
  }

  async issue({ deviceId, ttlMs }) {
    if (!Number.isInteger(ttlMs) || ttlMs <= 0) {
      throw new Error('ttlMs must be positive');
    }

    return withFileLock(this.path, async () => {
      const issuedAt = this.now();
      const expiresAt = new Date(issuedAt.getTime() + ttlMs);
      const token = this.randomBytes(32).toString('base64url');
      const tokens = validateTokenStore(await readJson(this.path, { tokens: [] }));
      tokens.tokens.push({
        id: `enr_${randomUUID().replaceAll('-', '')}`,
        deviceId,
        tokenHash: hashToken(token),
        issuedAt: issuedAt.toISOString(),
        expiresAt: expiresAt.toISOString(),
        consumedAt: null,
      });
      validateTokenStore(tokens);
      await writeJsonAtomic(this.path, tokens);

      return { token, expiresAt: expiresAt.toISOString() };
    }, { name: 'enrollment token store' });
  }

  async consume(token) {
    return withFileLock(this.path, async () => {
      const now = this.now();
      const tokens = validateTokenStore(await readJson(this.path, { tokens: [] }));
      const record = tokens.tokens.find(({ tokenHash }) => tokenHash === hashToken(token));

      if (!record) {
        throw new Error('unknown enrollment token');
      }
      if (record.consumedAt) {
        throw new Error('enrollment token already consumed');
      }
      if (now >= new Date(record.expiresAt)) {
        throw new Error('enrollment token expired');
      }

      record.consumedAt = now.toISOString();
      validateTokenStore(tokens);
      await writeJsonAtomic(this.path, tokens);
      return { deviceId: record.deviceId, expiresAt: record.expiresAt };
    }, { name: 'enrollment token store' });
  }

  async revoke(rawToken) {
    const tokenHash = hashToken(rawToken);

    return withFileLock(this.path, async () => {
      const tokens = validateTokenStore(await readJson(this.path, { tokens: [] }));
      const index = tokens.tokens.findIndex((record) => record.tokenHash === tokenHash);

      if (index === -1) {
        return false;
      }

      tokens.tokens.splice(index, 1);
      validateTokenStore(tokens);
      await writeJsonAtomic(this.path, tokens);
      return true;
    }, { name: 'enrollment token store' });
  }
}
