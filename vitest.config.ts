// The PNG/JPEG decode tests take ~1–5 s on a shared CI runner (5.3 s seen when they run in parallel); 5 s default is too tight.
export default { test: { include: ['test/**/*.test.ts'], environment: 'node', testTimeout: 30_000 } };
