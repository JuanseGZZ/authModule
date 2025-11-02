import { Models } from '../models/models.js';

export function validateEmail(value) {
  const ok = /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(String(value||'').trim());
  if (!ok) throw Models.makeErrorModel({ code:'VALIDATION_ERROR', message:'Email inválido', httpStatus:400 });
}

export function validatePasswordMin(value, min=6) {
  if (!value || String(value).length < min) {
    throw Models.makeErrorModel({ code:'VALIDATION_ERROR', message:`Contraseña muy corta (min ${min})`, httpStatus:400 });
  }
}
