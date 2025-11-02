// Global runtime config (can be overridden by window.__CONFIG__)
export const CONFIG = Object.freeze({
  API_BASE: (window.__CONFIG__ && window.__CONFIG__.API_BASE) || (typeof API_BASE !== 'undefined' ? API_BASE : ''),
  REFRESH_TRANSPORT: (window.__CONFIG__ && window.__CONFIG__.REFRESH_TRANSPORT) || 'cookie', // 'cookie' | 'body'
  SESSION_REFRESH_CHECK_INTERVAL_MS: (window.__CONFIG__ && window.__CONFIG__.SESSION_REFRESH_CHECK_INTERVAL_MS) || 30000,
  ACCESS_EXP_SOON_THRESHOLD_SEC: (window.__CONFIG__ && window.__CONFIG__.ACCESS_EXP_SOON_THRESHOLD_SEC) || 60,
  RATE_LIMIT_DEBOUNCE_MS: (window.__CONFIG__ && window.__CONFIG__.RATE_LIMIT_DEBOUNCE_MS) || 600,
});
