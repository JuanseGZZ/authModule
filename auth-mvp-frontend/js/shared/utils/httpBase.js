import { Models } from '../models/models.js';
import { CONFIG } from './config.js';
import { toErrorModel } from './toErrorModel.js';

/**
 * httpBase({ method, url, headers, body })
 * - fetch with credentials:'include' to allow httpOnly cookies
 * - parse JSON; if !ok => throw ErrorModel
 */
export async function httpBase({ method='GET', url='', headers={}, body=undefined }) {
  const base = CONFIG.API_BASE || '';
  const fullUrl = base ? base.replace(/\/$/, '') + url : url;
  let resp;
  try {
    resp = await fetch(fullUrl, {
      method,
      headers: { 'Content-Type': 'application/json', ...headers },
      body: body !== undefined ? JSON.stringify(body) : undefined,
      credentials: 'include',
    });
  } catch (e) {
    throw Models.makeErrorModel({ code:'UNKNOWN', message:'No se pudo conectar con el servidor.', httpStatus:0 });
  }

  let data = null;
  const isJson = (resp.headers.get('content-type')||'').includes('application/json');
  if (isJson) {
    try { data = await resp.json(); } catch {}
  }

  if (!resp.ok) {
    throw toErrorModel(data, resp.status);
  }
  return data;
}
