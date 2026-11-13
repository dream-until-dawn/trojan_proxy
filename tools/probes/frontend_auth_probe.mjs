// 在隔离Node中执行真实前端模块和HTTP，不使用用户凭据或外部服务。
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import http from 'node:http';
import { performance } from 'node:perf_hooks';
import vm from 'node:vm';

const source = await readFile('internal/webui/assets/auth.js', 'utf8');
const counts = new Map();
const events = [];
const checks = [];
const fixtureToken = 'f'.repeat(43);
const server = http.createServer(async (request, response) => {
  const path = request.url.replace(/^\/proxy/, '');
  counts.set(path, (counts.get(path) || 0) + 1);
  for await (const chunk of request) { /* 仅排空虚构请求，不保存口令或正文。 */ }
  response.setHeader('Connection', 'close');
  if (path === '/api/never') return;
  if (path === '/api/slow-body') {
    response.writeHead(200, { 'Content-Type': 'application/json' });
    response.write('{');
    return;
  }
  if (path === '/api/disconnect') { request.socket.destroy(); return; }
  if (path === '/api/html') { response.end('<html>private-sentinel</html>'); return; }
  response.setHeader('Content-Type', 'application/json');
  if (path === '/api/null') { response.end('null'); return; }
  if (path === '/api/array') { response.end('[]'); return; }
  if (path === '/missing-token/api/login') { response.end('{}'); return; }
  if (path === '/api/error-object') {
    response.writeHead(500); response.end(JSON.stringify({ error: { secret: 'private-sentinel' } })); return;
  }
  if (path === '/api/bad-login') {
    response.writeHead(401); response.end(JSON.stringify({ error: '口令或验证码错误' })); return;
  }
  if (path === '/api/login') {
    response.end(JSON.stringify({ token: fixtureToken })); return;
  }
  if (path === '/api/denied' || request.headers.authorization !== 'Bearer ' + fixtureToken) {
    response.writeHead(401); response.end(JSON.stringify({ error: '请重新登录' })); return;
  }
  response.end(JSON.stringify({ ok: true, method: request.method, contentType: request.headers['content-type'] }));
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const base = `http://127.0.0.1:${server.address().port}`;

async function load(text, prefix = '') {
  const context = vm.createContext({ fetch, URL, AbortController, setTimeout, clearTimeout, Event,
    document: { dispatchEvent: event => events.push(event.type) } });
  const module = new vm.SourceTextModule(text, { context, identifier: base + prefix + '/auth.js',
    initializeImportMeta: meta => { meta.url = base + prefix + '/auth.js'; } });
  await module.link(() => { throw new Error('unexpected_dependency'); });
  await module.evaluate();
  return module.namespace;
}

async function rejectsMessage(operation, expected) {
  await assert.rejects(operation, error => expected.test(error.message) && !error.message.includes('private-sentinel'));
}

async function timeout(api, path) {
  const started = performance.now();
  let watchdog;
  try {
    await Promise.race([
      api.request(path).then(() => { throw new Error('unexpected_timeout_success'); }, error => {
        assert.match(error.message, /请求超过15秒/);
      }),
      new Promise((_, reject) => { watchdog = setTimeout(() => reject(new Error('timeout_guard_missing')), 22000); }),
    ]);
  } finally { clearTimeout(watchdog); }
  const elapsed = performance.now() - started;
  assert.ok(elapsed >= 14000 && elapsed < 22000, 'timeout_duration_outside_contract');
}

try {
  for (const prefix of ['', '/proxy']) {
    const api = await load(source, prefix);
    await api.login('disposable-password', 'otp', 'disposable-code');
    const status = await api.request('/api/status');
    assert.equal(status.ok, true); assert.equal(status.method, 'POST'); assert.equal(status.contentType, 'application/json');
    await rejectsMessage(() => api.request('/api/denied'), /请重新登录/);
    await rejectsMessage(() => api.request('/api/status'), /请重新登录/);
  }
  assert.equal(events.filter(name => name === 'authentication-expired').length, 2);
  checks.push('root_and_prefixed_login_bearer_and_401_revocation');
  const api = await load(source);
  await rejectsMessage(() => api.request('/api/bad-login'), /^口令或验证码错误$/);
  checks.push('credential_error_preserved');
  for (const path of ['/api/html', '/api/null', '/api/array']) await rejectsMessage(() => api.request(path), /不是管理接口内容/);
  await rejectsMessage(() => api.request('/api/error-object'), /请求失败，请刷新状态核对结果/);
  const misrouted = await load(source, '/missing-token');
  await rejectsMessage(() => misrouted.login('disposable-password','otp','disposable-code'), /不是管理接口内容/);
  checks.push('non_api_response_safely_classified');
  await rejectsMessage(() => api.request('/api/disconnect'), /未能连接管理入口/);
  checks.push('network_failure_classified');
  await timeout(api, '/api/never');
  assert.equal(counts.get('/api/never'), 1, 'timed_out_post_retried');
  checks.push('real_15s_header_timeout_without_retry');
  await timeout(api, '/api/slow-body');
  assert.equal(counts.get('/api/slow-body'), 1, 'body_timeout_post_retried');
  checks.push('real_15s_body_timeout_without_retry');
  // 只破坏待测试副本；必须由指定的超时保护缺失断言识别。
  const guard = 'signal: controller.signal,';
  assert.equal(source.split(guard).length, 2);
  const mutant = await load(source.replace(guard, ''));
  await assert.rejects(() => timeout(mutant, '/api/never'), /^Error: timeout_guard_missing$/);
  assert.equal(counts.get('/api/never'), 2, 'mutant_post_retried');
  checks.push('timeout_mutation_target_detected');
  console.log(JSON.stringify({ passed: true, node: process.version, checks, mutation_failure: 'timeout_guard_missing' }));
} finally {
  server.closeAllConnections();
  await new Promise(resolve => server.close(resolve));
}
