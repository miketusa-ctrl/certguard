// Cloudflare Workers TCP transport (plain TCP; TLS is done manually in tls.js).
import { connect } from 'cloudflare:sockets';

export async function workerTransport(ip, port) {
  const hostname = ip.includes(':') ? `[${ip}]` : ip;
  const socket = connect({ hostname, port }, { secureTransport: 'off', allowHalfOpen: false });
  await socket.opened;
  const writer = socket.writable.getWriter();
  const reader = socket.readable.getReader();
  return {
    write: (b) => writer.write(b),
    read: async () => { const { value, done } = await reader.read(); return done ? null : value; },
    close: () => { try { socket.close().catch(() => {}); } catch { /* ignore */ } },
  };
}
