import { Models } from '../models/models.js';

export function toErrorModel(json, httpStatus) {
  let code = 'UNKNOWN';
  let message = 'Error desconocido.';
  if (json && typeof json === 'object') {
    if (json.error && typeof json.error === 'object') {
      code = json.error.code || code;
      message = json.error.message || message;
    } else if (json.code || json.message) {
      code = json.code || code;
      message = json.message || message;
    }
  }
  return Models.makeErrorModel({ code, message, httpStatus });
}
