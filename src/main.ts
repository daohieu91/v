import { parseCheckedAt } from './attestation-date';
import { guardFraming } from './framing';
guardFraming(window);
document.getElementById('app')!.textContent = 'CameraStamp';
const note = document.getElementById('attested')!;
fetch(import.meta.env.BASE_URL + 'attestation/meta.json')
  .then((r) => r.json())
  .then((j) => { note.textContent = 'Google attestation data copied on ' + (parseCheckedAt(j) ?? 'an unknown date'); })
  .catch(() => { note.textContent = 'Google attestation data date unavailable'; });
