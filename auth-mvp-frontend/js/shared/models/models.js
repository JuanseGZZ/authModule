/**
 * TokenModel: { accessToken, accessExpEpochSec, refreshTransport }
 * UserModel : { id, email, roles }
 * ErrorModel: { code, message, httpStatus }
 * SessionState: { isAuthenticated, lastRefreshAt? }
 */
export const Models = Object.freeze({
  makeTokenModel: ({ accessToken, accessExpEpochSec, refreshTransport }) => ({ accessToken, accessExpEpochSec, refreshTransport }),
  makeUserModel: ({ id, email, roles }) => ({ id, email, roles: Array.isArray(roles)? roles : [] }),
  makeErrorModel: ({ code='UNKNOWN', message='Error desconocido.', httpStatus=0 }) => ({ code, message, httpStatus }),
});
