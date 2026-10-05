import { guardFraming } from '../framing';
guardFraming(window);
// Task 22 replaces this with the C2PA reader. Until then level 2 answers "not available" at once, so a picked original file never
// waits for the 60 s bridge timeout. Only our own origin is answered.
window.addEventListener('message', (e: MessageEvent) => { if (e.origin === location.origin) e.ports[0]?.postMessage(null); });
