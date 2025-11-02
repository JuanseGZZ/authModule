import { sessionRender } from '../../pages/session/render.js';
import { sessionService } from '../../pages/session/service.js';
import { authState } from '../../shared/service/authState.js';
import { uiAuthState } from '../../shared/render/uiAuthState.js';
import { CONFIG } from '../../shared/utils/config.js';
import { tokenStore } from '../../shared/service/tokenStore.js';

export function initSessionModule() {
  // Logout button
  const btnLogout = document.getElementById('btnLogout');
  btnLogout?.addEventListener('click', async () => {
    try { await sessionService.logout(); } finally { sessionRender.logoutSuccess(); }
  });

  // Session expired handler
  document.addEventListener('session:expired', () => {
    sessionRender.expired();
  });

  // Periodic refresh (access nearing expiration)
  setInterval(async () => {
    try {
      if (tokenStore.isExpiringSoon(CONFIG.ACCESS_EXP_SOON_THRESHOLD_SEC)) {
        await sessionService.refresh();
      }
    } catch (e) {
      document.dispatchEvent(new Event('session:expired'));
    }
  }, CONFIG.SESSION_REFRESH_CHECK_INTERVAL_MS);
}
