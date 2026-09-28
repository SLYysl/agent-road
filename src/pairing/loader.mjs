import { normalizePairCode, pairingError } from './protocol.mjs';

// The code locates an invitation; it is not permission to execute a bootstrap.
export function buildJoinCommand(origin, code) {
  if (!/^https:\/\/[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(origin ?? '')) throw pairingError('PAIR_INPUT_INVALID');
  return `irm '${origin}/join.ps1?code=${normalizePairCode(code)}' | iex`;
}

export function renderPairLoader(request, origin, source) {
  const url = new URL(request.url);
  if (request.method !== 'GET' || url.pathname !== '/join.ps1') return null;
  if (!/^https:\/\/[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(origin ?? '')) throw pairingError('PAIR_SERVICE_UNCONFIGURED', 503);
  const keys = [...url.searchParams.keys()];
  if (keys.some(key => key !== 'code') || keys.length > 1) throw pairingError('PAIR_INPUT_INVALID');
  const code = keys.length ? normalizePairCode(url.searchParams.get('code')) : '';
  return new Response(source.replaceAll('__PAIR_ORIGIN__', origin).replaceAll('__PAIR_CODE__', code), {
    headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer' },
  });
}
