import { httpBase } from './httpBase.js';
import { authHeaderBuilder } from './authHeaderBuilder.js';
import { tokenStore } from '../service/tokenStore.js';
import { authState } from '../service/authState.js';
import { sessionService } from '../../pages/session/service.js';
import { toErrorModel } from './toErrorModel.js';

/**
 * withAuthFetch wraps httpBase injecting Authorization and handling 401 by trying a single refresh.
 */
export async function withAuthFetch({ method='GET', url='', headers={}, body=undefined }) {
  const firstHeaders = { ...headers, ...authHeaderBuilder() };
  try {
    return await httpBase({ method, url, headers: firstHeaders, body });
  } catch (err) {
    const em = toErrorModel(err, err.httpStatus||0);
    if (em.httpStatus === 401 || em.code === 'AUTH_TOKEN_EXPIRED') {
      try {
        await sessionService.refresh(); // will update tokenStore or throw
        const retryHeaders = { ...headers, ...authHeaderBuilder() };
        return await httpBase({ method, url, headers: retryHeaders, body });
      } catch (e2) {
        authState.dispatch('session:expired');
        throw e2;
      }
    }
    throw err;
  }
}
