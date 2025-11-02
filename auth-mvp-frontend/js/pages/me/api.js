import { withAuthFetch } from '../../shared/utils/withAuthFetch.js';

export const meApi = Object.freeze({
  getProfile() {
    return withAuthFetch({ method:'GET', url:'/auth/me' });
  }
});
