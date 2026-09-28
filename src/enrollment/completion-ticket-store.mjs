import { createHash, randomBytes as cryptoRandomBytes } from 'node:crypto';

const DEVICE_ID_PATTERN = /^dev_[a-z0-9]+$/;
const MAX_DEVICE_ID_LENGTH = 64;
const RAW_TICKET_PATTERN = /^[A-Za-z0-9_-]{43}$/;

function invalidTicketError() {
  return new Error('invalid completion ticket');
}

function readTime(now) {
  const value = now();
  if (!(value instanceof Date) || Number.isNaN(value.getTime())) {
    throw new Error('invalid completion ticket clock');
  }
  return value.getTime();
}

function hashTicket(rawTicket) {
  return createHash('sha256').update(rawTicket, 'utf8').digest('hex');
}

function isValidDeviceId(value) {
  return typeof value === 'string'
    && value.length <= MAX_DEVICE_ID_LENGTH
    && DEVICE_ID_PATTERN.test(value);
}

export class CompletionTicketStore {
  #now;
  #randomBytes;
  #records = new Map();
  #queue = Promise.resolve();

  constructor({ now = () => new Date(), randomBytes = cryptoRandomBytes } = {}) {
    if (typeof now !== 'function' || typeof randomBytes !== 'function') {
      throw new TypeError('invalid completion ticket dependency');
    }
    this.#now = now;
    this.#randomBytes = randomBytes;
  }

  #runExclusive(operation) {
    const result = this.#queue.then(operation);
    this.#queue = result.then(() => undefined, () => undefined);
    return result;
  }

  async issue(deviceId, ttlMs) {
    if (
      !isValidDeviceId(deviceId)
      || !Number.isSafeInteger(ttlMs)
      || ttlMs <= 0
    ) {
      throw new Error('invalid completion ticket request');
    }

    return this.#runExclusive(() => {
      const issuedAt = readTime(this.#now);
      const expiresAt = issuedAt + ttlMs;
      if (!Number.isSafeInteger(expiresAt) || expiresAt <= issuedAt) {
        throw new Error('invalid completion ticket request');
      }
      const entropy = this.#randomBytes(32);
      if (!Buffer.isBuffer(entropy) || entropy.length !== 32) {
        throw new Error('invalid completion ticket entropy');
      }
      const rawTicket = entropy.toString('base64url');
      const ticketHash = hashTicket(rawTicket);
      if (this.#records.has(ticketHash)) {
        throw new Error('invalid completion ticket entropy');
      }
      this.#records.set(ticketHash, Object.freeze({ deviceId, issuedAt, expiresAt }));
      return rawTicket;
    });
  }

  async consume(rawTicket, deviceId) {
    if (
      typeof rawTicket !== 'string'
      || !RAW_TICKET_PATTERN.test(rawTicket)
      || Buffer.from(rawTicket, 'base64url').length !== 32
      || !isValidDeviceId(deviceId)
    ) {
      throw invalidTicketError();
    }

    return this.#runExclusive(() => {
      const now = readTime(this.#now);
      const ticketHash = hashTicket(rawTicket);
      const record = this.#records.get(ticketHash);
      if (
        !record
        || record.deviceId !== deviceId
        || now < record.issuedAt
        || now >= record.expiresAt
      ) {
        throw invalidTicketError();
      }
      this.#records.delete(ticketHash);
      return Object.freeze({ deviceId: record.deviceId });
    });
  }
}
