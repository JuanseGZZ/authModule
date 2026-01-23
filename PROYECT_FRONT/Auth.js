// este va a llevar todo el core de la app


// Auth.js
import { AuthService } from "./Services.js";

const auth = new AuthService();

function randomEmail() {
  const n = Math.floor(Math.random() * 1e9);
  return `test${n}@test.com`;
}

(async () => {
  // AES "de prueba": en serio, en prod debe ser random y guardada por usuario/sesion.
  const aeskey = "12345678901234567890123456789012"; // 32 chars

  const email = randomEmail();
  const username = email.split("@")[0];
  const password = "1234";

  console.log("Registrando:", { email, username, password });

  const reg = await auth.register({
    email,
    username,
    password,
    aeskey
  });

  console.log("REGISTER DEC:", reg);

  const login = await auth.login({
    emailOrUsername: email,
    password,
    aeskey
  });

  console.log("LOGIN DEC:", login);
})();
