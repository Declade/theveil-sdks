import { afterAll, afterEach, beforeAll } from 'vitest';
import { server } from './test-server.js';

// `onUnhandledRequest: 'error'` makes any unexpected network call fail the
// test rather than hit the real internet.
beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());
