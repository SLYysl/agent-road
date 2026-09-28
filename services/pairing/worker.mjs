import { authRequest } from '../../src/auth/service.mjs';
import { renderPairLoader } from '../../src/pairing/loader.mjs';
import { DurableObject } from 'cloudflare:workers';
import { expirePairs, jsonResponse, serviceRequest } from '../../src/pairing/service.mjs';
import loader from '../../windows/pairing/join.ps1';
export class PairingRegistry extends DurableObject {
  async fetch(request) {
    return this.ctx.blockConcurrencyWhile(() => new URL(request.url).pathname.startsWith('/api/cli/') ? authRequest(request, this.env, this.ctx.storage) : serviceRequest(request, this.env, this.ctx.storage));
  }
  async alarm() { await this.ctx.blockConcurrencyWhile(() => expirePairs(this.ctx.storage)); }
}
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.protocol !== 'https:' && url.hostname !== 'localhost' && url.hostname !== '127.0.0.1') return jsonResponse({ code: 'PAIR_HTTPS_REQUIRED' }, 400);
    if (request.method === 'GET' && url.pathname === '/health') return jsonResponse({ service: 'agent-road-pairing', protocolVersion: 1 });
    try {
      const response = renderPairLoader(request, env.PUBLIC_ORIGIN, loader);
      if (response) return response;
    } catch (error) {
      return jsonResponse({ code: error.code === 'PAIR_SERVICE_UNCONFIGURED' ? error.code : 'PAIR_INPUT_INVALID' }, error.code === 'PAIR_SERVICE_UNCONFIGURED' ? 503 : 400);
    }
    if (request.method === 'POST' && /^\/api\/cli\/(start|status|inspect|approve|deny|list|revoke|logout)$/.test(url.pathname) && !url.search) return env.PAIRINGS.get(env.PAIRINGS.idFromName('private-controller-v1')).fetch(request);
    if (request.method !== 'POST' || !/^\/v[12]\/(create|claim|status|approve|receive|cancel)$/.test(url.pathname) || url.search) return jsonResponse({ code: 'PAIR_NOT_FOUND' }, 404);
    return env.PAIRINGS.get(env.PAIRINGS.idFromName('private-controller-v1')).fetch(request);
  },
};
