import { Models } from '../models/models.js';
import { CONFIG } from '../utils/config.js';

let accessToken = null;
let accessExpEpochSec = null;

// Optional: refresh storage (only used when REFRESH_TRANSPORT='body')
const REFRESH_KEY = 'AUTH_MVP_REFRESH_TOKEN';

export const tokenStore = Object.freeze({
  setAccess(token, expiresInSec) {
    accessToken = token || null;
    const nowSec = Math.floor(Date.now()/1000);
    accessExpEpochSec = token ? (nowSec + (Number(expiresInSec)||0)) : null;
  },
  getAccess() { return accessToken; },
  getAccessExpEpochSec() { return accessExpEpochSec; },
  clear() { accessToken = null; accessExpEpochSec = null; sessionStorage.removeItem(REFRESH_KEY); },
  isExpiringSoon(thresholdSec) {
    if (!accessToken || !accessExpEpochSec) return false;
    const now = Math.floor(Date.now()/1000);
    return (accessExpEpochSec - now) <= (Number(thresholdSec)||60);
  },
  // refresh token helpers (body mode only)
  setRefreshOpaqueIfBodyMode(refreshToken) {
    if (CONFIG.REFRESH_TRANSPORT === 'body' && typeof refreshToken === 'string') {
      sessionStorage.setItem(REFRESH_KEY, refreshToken);
    }
  },
  getRefreshOpaqueIfBodyMode() {
    if (CONFIG.REFRESH_TRANSPORT === 'body') return sessionStorage.getItem(REFRESH_KEY);
    return null;
  }
});
