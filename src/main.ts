// The entry chunk: plain old syntax and NO BigInt literal, so a browser too old for the core (BigInt, 64-bit DataView, Worker) can still
// parse it and shows the "too old" note in index.html instead of a blank page. The core loads as a separate chunk only after the check.
import { guardFraming } from './framing';
guardFraming(window);
var old = document.getElementById('too-old');
var dv = typeof DataView === 'function' ? (DataView.prototype as unknown as Record<string, unknown>) : null;
var ok = typeof BigInt === 'function' && !!dv && typeof dv.getBigUint64 === 'function' && typeof Worker === 'function' && typeof Promise === 'function';
var tooOld = function () { if (old) { old.className = 'too-old now'; if (!old.parentNode) document.body.insertBefore(old, document.body.firstChild); } };
if (!ok) tooOld();
else { if (old && old.parentNode) old.parentNode.removeChild(old); import('./app').catch(tooOld); }
