import { setupServer } from 'msw/node';

// Shared MSW server for SDK tests. Start with no handlers — each test file
// adds handlers via `server.use(...)` so expectations are colocated with the
// behaviour under test and isolated per-case.
export const server = setupServer();
