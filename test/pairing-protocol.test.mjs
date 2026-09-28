import assert from 'node:assert/strict';
import test from 'node:test';
import { createPairRecord, pairTransition, normalizePairCode, validateBootstrap, digestToken, PAIR_TTL_MS } from '../src/pairing/protocol.mjs';
const ownerHash = 'a'.repeat(64), clientHash = 'b'.repeat(64), wrong = 'c'.repeat(64);
const fresh = () => createPairRecord({ ownerHash, now: 1000 });
const claim = (r) => pairTransition(r, 'claim', { clientHash, verification: '12345678' }, 1001).record;
const approve = (r) => pairTransition(r, 'approve', { ownerHash, claimId: clientHash, envelope: 'encrypted-fixture' }, 1002).record;
const code = (value) => (e) => e.code === value;
test('normal path requires claim and owner approval, delivers once, and erases live envelope', () => {
 let r = claim(fresh());
 assert.deepEqual(pairTransition(r, 'receive', { clientHash }, 1002).response, { state: 'PENDING' });
 assert.equal(pairTransition(r, 'status', { ownerHash }, 1002).response.claim.id, clientHash);
 r = approve(r);
 const result = pairTransition(r, 'receive', { clientHash }, 1003);
 assert.equal(result.response.envelope, 'encrypted-fixture');
 assert.equal(result.record.envelope, null);
 assert.throws(() => pairTransition(result.record, 'receive', { clientHash }, 1004), code('PAIR_UNAVAILABLE'));
 assert.equal(r.state, 'APPROVED', 'transition does not mutate caller input');
});
test('wrong owner, wrong claimant and stale approval cannot release payload', () => {
 const r = claim(fresh());
 for (const action of ['status', 'cancel', 'approve']) assert.throws(() => pairTransition(r, action, { ownerHash: wrong }, 1002), code('PAIR_UNAUTHORIZED'));
 assert.throws(() => pairTransition(r, 'receive', { clientHash: wrong }, 1002), code('PAIR_UNAUTHORIZED'));
 assert.throws(() => pairTransition(r, 'approve', { ownerHash, claimId: wrong, envelope: 'x' }, 1002), code('PAIR_CLAIM_CHANGED'));
 assert.throws(() => pairTransition(r, 'claim', { clientHash: wrong, verification: '87654321' }, 1002), code('PAIR_ALREADY_CLAIMED'));
});
test('expiry, cancellation and clock rollback fail closed', () => {
 const r = approve(claim(fresh()));
 for(const now of [999, 1000 + PAIR_TTL_MS]) assert.throws(() => pairTransition(r, 'receive', { clientHash }, now), code('PAIR_EXPIRED'));
 const cancelled = pairTransition(r, 'cancel', { ownerHash }, 1003).record;
 assert.equal(cancelled.envelope, null);
 assert.throws(() => pairTransition(cancelled, 'receive', { clientHash }, 1004), code('PAIR_UNAVAILABLE'));
});
test('short codes normalize, bootstrap shape is fixed, credentials are hashed', async () => {
 assert.equal(normalizePairCode('abcd-efgh-jkmn'), 'ABCDEFGHJKMN');
 for (const value of ['1234', 'ABCD/EFGH/JKMN', '../etc/passwd', 'ABCD-EFGH-IJKL']) assert.throws(() => normalizePairCode(value));
 assert.equal(validateBootstrap('powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand QQ==').endsWith('QQ=='), true);
 for (const value of ['echo hi', 'powershell.exe -EncodedCommand QQ==', 'x'.repeat(33000)]) assert.throws(() => validateBootstrap(value));
 assert.match(await digestToken('A'.repeat(43)), /^[a-f0-9]{64}$/);
 assert.notEqual(await digestToken('A'.repeat(43)), await digestToken('B'.repeat(43)));
});
