import { tokenStore } from './tokenStore.js';

const bus = new EventTarget();

export const authState = Object.freeze({
  isAuthenticated() { return !!tokenStore.getAccess(); },
  on(eventName, handler) { bus.addEventListener(eventName, handler); },
  off(eventName, handler) { bus.removeEventListener(eventName, handler); },
  dispatch(eventName, detail) { bus.dispatchEvent(new CustomEvent(eventName, { detail })); },
});
