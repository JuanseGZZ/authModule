import { httpBase } from '../../shared/utils/httpBase.js';
import { CONFIG } from '../../shared/utils/config.js';
import { tokenStore } from '../../shared/service/tokenStore.js';

export const sessionApi = Object.freeze({
  refresh() {
    if (CONFIG.REFRESH_TRANSPORT === 'body') {
      const rt = tokenStore.getRefreshOpaqueIfBodyMode();
      return httpBase({ method:'POST', url:'/auth/token/refresh', body:{ refresh_token: rt } });
    }
    // cookie mode
    return httpBase({ method:'POST', url:'/auth/token/refresh' });
  },
  logout() {
    if (CONFIG.REFRESH_TRANSPORT === 'body') {
      const rt = tokenStore.getRefreshOpaqueIfBodyMode();
      return httpBase({ method:'POST', url:'/auth/logout', body:{ refresh_token: rt } });
    }
    return httpBase({ method:'POST', url:'/auth/logout' });
  }
});
