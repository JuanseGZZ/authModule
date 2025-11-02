import { tokenStore } from '../service/tokenStore.js';

export function authHeaderBuilder() {
  const at = tokenStore.getAccess();
  return at ? { Authorization: `Bearer ${at}` } : {};
}
