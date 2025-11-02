import { httpBase } from '../../shared/utils/httpBase.js';

export const loginApi = Object.freeze({
  login(email, password) {
    return httpBase({ method:'POST', url:'/auth/login', body:{ email, password } });
  }
});
