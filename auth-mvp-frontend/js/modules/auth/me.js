import { meService } from '../../pages/me/service.js';
import { meRender } from '../../pages/me/render.js';

export const meController = Object.freeze({
  async fetchMe() {
    try {
      const user = await meService.getProfile();
      meRender.profile(user);
    } catch (err) {
      meRender.error(err);
    }
  }
});
