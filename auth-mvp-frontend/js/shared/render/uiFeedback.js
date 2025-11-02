import { ERROR_MESSAGES } from '../utils/errorMessagesMap.js';

const toastEl = () => document.getElementById('toast');

export const uiFeedback = Object.freeze({
  toastOk(msg='OK') { showToast(msg); },
  toastInfo(msg='Info') { showToast(msg); },
  toastError(msg='Error') { showToast(msg); },
  mapErrorToMessage(errorModel) {
    if (!errorModel || !errorModel.code) return ERROR_MESSAGES.UNKNOWN;
    return ERROR_MESSAGES[errorModel.code] || ERROR_MESSAGES.UNKNOWN;
  }
});

function showToast(text) {
  const t = toastEl();
  if (!t) return;
  t.textContent = text;
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 2500);
}
