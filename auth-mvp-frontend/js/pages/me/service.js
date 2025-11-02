import { meApi } from './api.js';
import { Models } from '../../shared/models/models.js';

export const meService = Object.freeze({
  async getProfile() {
    const res = await meApi.getProfile();
    return Models.makeUserModel(res);
  }
});
