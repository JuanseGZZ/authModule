import { authState } from '../service/authState.js';

const navLogin = () => document.getElementById('navLogin');
const navRegister = () => document.getElementById('navRegister');
const navMe = () => document.getElementById('navMe');
const btnLogout = () => document.getElementById('btnLogout');

export const uiAuthState = Object.freeze({
  toAuthenticated() {
    if (navLogin()) navLogin().style.display = 'none';
    if (navRegister()) navRegister().style.display = 'none';
    if (navMe()) navMe().style.display = '';
    if (btnLogout()) btnLogout().style.display = '';
  },
  toUnauthenticated() {
    if (navLogin()) navLogin().style.display = '';
    if (navRegister()) navRegister().style.display = '';
    if (navMe()) navMe().style.display = 'none';
    if (btnLogout()) btnLogout().style.display = 'none';
  },
  syncNav() {
    if (authState.isAuthenticated()) this.toAuthenticated();
    else this.toUnauthenticated();
  }
});
