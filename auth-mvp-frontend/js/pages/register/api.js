import { httpBase } from '../../shared/utils/httpBase.js';

export const registerApi = Object.freeze({
  register(email, password) {
    return httpBase({ method:'POST', url:'/auth/register', body:{ email, password } });
  }
});
