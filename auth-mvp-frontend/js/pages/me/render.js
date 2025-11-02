import { uiFeedback } from '../../shared/render/uiFeedback.js';
import { showView } from '../../shared/render/showView.js';

export const meRender = Object.freeze({
  profile(user) {
    const box = document.getElementById('meContent');
    if (box) {
      box.innerHTML = `
        <div><strong>ID:</strong> ${user.id}</div>
        <div><strong>Email:</strong> ${user.email}</div>
        <div><strong>Roles:</strong> ${(user.roles||[]).join(', ')}</div>
      `;
    }
    document.getElementById('meMsg').textContent = '';
  },
  error(errorModel) {
    // If expired, the withAuthFetch flow will dispatch session:expired
    const msg = document.getElementById('meMsg');
    if (msg) msg.textContent = uiFeedback.mapErrorToMessage(errorModel);
  }
});
