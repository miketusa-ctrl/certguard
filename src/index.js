import { createApp } from './app.js';
import { workerTransport } from './socket.js';

export default createApp({ transportFactory: workerTransport, timeoutMs: 7000 });
