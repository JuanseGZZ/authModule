import { registerService } from '../../pages/register/service.js';
import { registerRender } from '../../pages/register/render.js';

export function initRegisterModule() {
  const form = document.getElementById('formRegister');
  form?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const email = document.getElementById('registerEmail')?.value;
    const password = document.getElementById('registerPassword')?.value;
    try {
      const result = await registerService.register(email, password);
      registerRender.success(result);
    } catch (err) {
      registerRender.error(err);
    }
  });
}
