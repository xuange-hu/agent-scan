import { spawn } from 'node:child_process';
import { TOOL_VERSION } from '../util.js';

// Minimal MCP stdio client (newline-delimited JSON-RPC 2.0), zero deps.
// Safety contract: we ONLY perform the initialize handshake and metadata
// listing (tools/prompts/resources). No tool is ever invoked, no content is
// read beyond what the server pushes before we close it. The process is
// killed as soon as the capture completes or the deadline expires.

const PROTOCOL_VERSION = '2025-03-26';

class ProbeError extends Error {}

export async function captureMcpMetadata(command, args = [], { timeoutMs = 15000 } = {}) {
  const child = spawn(command, args, { stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true });

  let stdoutBuf = '';
  let stderrBuf = '';
  let closed = false;
  const pending = new Map();

  const deadline = setTimeout(() => done(new ProbeError(
    `probe timed out after ${timeoutMs}ms while talking to "${command}"`)), timeoutMs);

  child.stdout.setEncoding('utf8');
  child.stderr.setEncoding('utf8');

  let settle = () => {};
  const finished = new Promise((_, rej) => { settle = rej; });

  function done(err) {
    if (closed) return;
    closed = true;
    clearTimeout(deadline);
    try { child.kill('SIGKILL'); } catch { /* already gone */ }
    if (err) settle(err);
  }

  child.on('error', (err) => done(new ProbeError(
    `cannot launch "${command}": ${err.code === 'ENOENT' ? 'command not found' : err.message}`)));
  child.on('close', (code) => done(new ProbeError(
    `server exited (code ${code}) before the handshake completed${stderrBuf ? ` — last stderr: ${stderrBuf.slice(-200)}` : ''}`)));
  child.stderr.on('data', (chunk) => {
    stderrBuf = (stderrBuf + chunk).slice(-2000);
  });

  child.stdout.on('data', (chunk) => {
    stdoutBuf += chunk;
    let nl;
    while ((nl = stdoutBuf.indexOf('\n')) !== -1) {
      const line = stdoutBuf.slice(0, nl).trim();
      stdoutBuf = stdoutBuf.slice(nl + 1);
      if (!line) continue;
      let msg;
      try { msg = JSON.parse(line); } catch { continue; } // tolerate log noise on stdout
      if (msg.id !== undefined && pending.has(msg.id)) {
        const { resolve, reject } = pending.get(msg.id);
        pending.delete(msg.id);
        if (msg.error) reject(new ProbeError(`${msg.error.code ?? 'rpc'}: ${msg.error.message ?? 'error'}`));
        else resolve(msg.result);
      }
      // server-initiated requests/notifications: captured and ignored by design
    }
  });

  let nextId = 1;
  function request(method, params) {
    if (closed) return Promise.reject(new ProbeError('probe already finished'));
    const id = nextId++;
    return new Promise((resolve, reject) => {
      pending.set(id, { resolve, reject });
      child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n', (err) => {
        if (err) { pending.delete(id); reject(new ProbeError(`failed to write to server stdin: ${err.message}`)); }
      });
    });
  }

  try {
    const init = await Promise.race([
      request('initialize', {
        protocolVersion: PROTOCOL_VERSION,
        capabilities: {},
        clientInfo: { name: 'agent-scan-probe', version: TOOL_VERSION },
      }),
      finished,
    ]);
    child.stdin.write(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) + '\n');

    const tools = await listAll('tools/list', 'tools');
    const prompts = await listOptional('prompts/list', 'prompts');
    const resources = await listOptional('resources/list', 'resources');

    done();
    return { serverInfo: init?.serverInfo ?? {}, protocolVersion: init?.protocolVersion ?? '?', tools, prompts, resources };
  } catch (err) {
    done();
    throw err instanceof ProbeError ? err : new ProbeError(err.message);
  }

  async function listAll(method, key) {
    const items = [];
    let cursor;
    do {
      const result = await request(method, cursor ? { cursor } : {});
      items.push(...(result?.[key] ?? []));
      cursor = result?.nextCursor ?? undefined;
    } while (cursor);
    return items;
  }

  async function listOptional(method, key) {
    try {
      return await listAll(method, key);
    } catch (err) {
      if (/^-32601/.test(err.message)) return []; // method not supported
      throw err;
    }
  }
}
