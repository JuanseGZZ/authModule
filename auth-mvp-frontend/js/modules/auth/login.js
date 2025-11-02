import { loginService } from '../../pages/login/service.js';
import { loginRender } from '../../pages/login/render.js';

export function initLoginModule() {
  const showPass = document.getElementById('showPassLogin');
  const pwd = document.getElementById('loginPassword');
  showPass?.addEventListener('change', () => {
    if (pwd) pwd.type = showPass.checked ? 'text' : 'password';
  });

  const form = document.getElementById('formLogin');
  form?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const email = document.getElementById('loginEmail')?.value;
    const password = document.getElementById('loginPassword')?.value;
    try {
      await loginService.login(email, password);
      loginRender.success();
    } catch (err) {
      loginRender.error(err);
    }
  });
}
