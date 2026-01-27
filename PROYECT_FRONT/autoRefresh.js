import { getSessionOrNull, setSessionFromDecoded } from "./ModelSession.js";
import { AuthService } from "./Services.js";
import { StatefulEnabled, JWTExpires } from "./Env.js";

const svc = new AuthService();

let timerId = null;
let refreshInFlight = null;

export function stopAutoRefresh() {
  if (timerId) {
    clearTimeout(timerId);
    timerId = null;
  }
}

export function startAutoRefresh() {
  stopAutoRefresh();

  const s = getSessionOrNull();
  if (!s) return;

  const delayMin = JWTExpires - 2;
  if (delayMin <= 0) return;

  const delayMs = delayMin * 60 * 1000;
  timerId = setTimeout(runRefresh, delayMs);
}

async function runRefresh() {
  console.log("refrescando")
  if (refreshInFlight) return refreshInFlight;

  const s = getSessionOrNull();
  if (!s) return;

  refreshInFlight = (async () => {
    let decoded;

    try {
      if (StatefulEnabled) {
        decoded = await svc.refreshStateful({
          user_id: s.user_id,
          aes_old: s.aes,
          refresh_token: s.refresh_token
        });
      } else {
        decoded = await svc.refreshStateless({
          aeskey: s.aes,
          refresh_token: s.refresh_token
        });
      }

      setSessionFromDecoded(decoded);
    } finally {
      refreshInFlight = null;
      startAutoRefresh(); // reprogramar
    }
  })();

  return refreshInFlight;
}

