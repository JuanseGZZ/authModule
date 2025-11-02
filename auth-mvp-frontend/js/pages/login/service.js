import { loginApi } from './api.js';
import { validateEmail, validatePasswordMin } from '../../shared/utils/formValidators.js';
import { tokenStore } from '../../shared/service/tokenStore.js';
import { authState } from '../../shared/service/authState.js';
import { CONFIG } from '../../shared/utils/config.js';

export const loginService = Object.freeze({
  async login(email, password) {
    validateEmail(email);
    validatePasswordMin(password, 6);
    const res = await loginApi.login(email, password);
    if (res && res.access_token) {
      tokenStore.setAccess(res.access_token, res.expires_in || 900);
      if (CONFIG.REFRESH_TRANSPORT === 'body' && res.refresh_token) {
        tokenStore.setRefreshOpaqueIfBodyMode(res.refresh_token);
      }
      authState.dispatch('authenticated');
    }
    return {{ accessToken: res?.access_token || null, accessExpEpochSec: null, refreshTransport: CONFIG.REFRESH_TRANSPORT }};
  }
});
