import { showView } from '../shared/render/showView.js';
import { uiAuthState } from '../shared/render/uiAuthState.js';
import { meController } from './auth/me.js';

export function initNavigation() {
  const navLogin = document.getElementById('navLogin');
  const navRegister = document.getElementById('navRegister');
  const navMe = document.getElementById('navMe');

  navLogin?.addEventListener('click', () => showView('viewLogin'));
  navRegister?.addEventListener('click', () => showView('viewRegister'));
  navMe?.addEventListener('click', () => { 
    showView('viewMe');
    meController.fetchMe();
  });

  uiAuthState.syncNav();
}
