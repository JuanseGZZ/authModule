import { sessionApi } from './api.js';
import { tokenStore } from '../../shared/service/tokenStore.js';
import { Models } from '../../shared/models/models.js';
import { authState } from '../../shared/service/authState.js';
import { CONFIG } from '../../shared/utils/config.js';

export const sessionService = Object.freeze({
  async refresh() {
    const res = await sessionApi.refresh();
    if (res && res.access_token) {
      tokenStore.setAccess(res.access_token, res.expires_in || 900);
      if (CONFIG.REFRESH_TRANSPORT === 'body' && res.refresh_token) {
        tokenStore.setRefreshOpaqueIfBodyMode(res.refresh_token);
      }
      return true;
    }
    throw Models.makeErrorModel({ code:'AUTH_REFRESH_NOT_FOUND', message:'No refresh', httpStatus:401 });
  },
  async logout() {
    try { await sessionApi.logout(); } finally {
      tokenStore.clear();
      authState.dispatch('session:expired');
    }
  }
});
