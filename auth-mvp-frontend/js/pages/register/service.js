import { registerApi } from './api.js';
import { validateEmail, validatePasswordMin } from '../../shared/utils/formValidators.js';
import { Models } from '../../shared/models/models.js';

export const registerService = Object.freeze({
  async register(email, password) {
    validateEmail(email);
    validatePasswordMin(password, 6);
    const res = await registerApi.register(email, password);
    return Models.makeUserModel(res);
  }
});
