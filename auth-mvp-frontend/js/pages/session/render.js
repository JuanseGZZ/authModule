import { uiFeedback } from '../../shared/render/uiFeedback.js';
import { showView } from '../../shared/render/showView.js';
import { uiAuthState } from '../../shared/render/uiAuthState.js';

export const sessionRender = Object.freeze({
  expired() {
    uiAuthState.toUnauthenticated();
    showView('viewSessionExpired');
    uiFeedback.toastInfo('Tu sesión expiró.');
    document.getElementById('gotoLoginFromExpired')?.addEventListener('click', () => {
      showView('viewLogin');
    }, { once:true });
  },
  logoutSuccess() {
    uiAuthState.toUnauthenticated();
    showView('viewLogin');
    uiFeedback.toastOk('Sesión cerrada');
  }
});
