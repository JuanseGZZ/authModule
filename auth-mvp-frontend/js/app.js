import { initNavigation } from './modules/navigation.js';
import { initRegisterModule } from './modules/auth/register.js';
import { initLoginModule } from './modules/auth/login.js';
import { initSessionModule } from './modules/auth/session.js';
import { uiAuthState } from './shared/render/uiAuthState.js';
import { showView } from './shared/render/showView.js';

// Boot
window.addEventListener('DOMContentLoaded', () => {
  initNavigation();
  initRegisterModule();
  initLoginModule();
  initSessionModule();
  uiAuthState.syncNav();
  // default view
  showView('viewLogin');
});
