import { uiFeedback } from '../../shared/render/uiFeedback.js';

export const registerRender = Object.freeze({
  success(result) {
    const el = document.getElementById('registerMsg');
    if (el) el.textContent = 'Registro exitoso. Ahora podés iniciar sesión.';
    uiFeedback.toastOk('Cuenta creada');
  },
  error(errorModel) {
    const el = document.getElementById('registerMsg');
    if (el) el.textContent = uiFeedback.mapErrorToMessage(errorModel);
    uiFeedback.toastError(el?.textContent || 'Error');
  }
});
