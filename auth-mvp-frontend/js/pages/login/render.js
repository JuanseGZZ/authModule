import { uiAuthState } from '../../shared/render/uiAuthState.js';
import { uiFeedback } from '../../shared/render/uiFeedback.js';
import { showView } from '../../shared/render/showView.js';

export const loginRender = Object.freeze({
  success() {
    uiAuthState.toAuthenticated();
    showView('viewMe');
    uiFeedback.toastOk('Sesión iniciada');
  },
  error(errorModel) {
    const el = document.getElementById('loginMsg');
    if (el) el.textContent = uiFeedback.mapErrorToMessage(errorModel);
    uiFeedback.toastError(el?.textContent || 'Error');
  }
});
