// este va a llevar todo el core de la app

// Auth.js
import { AuthService } from "./Services.js";
import { Session,getSessionOrNull,setSessionFromDecoded,clearSession } from "./ModelSession.js"

const auth = new AuthService();

// funcion para hashear la password en el front
async function hashPassword(password) {
  const enc = new TextEncoder();
  const data = enc.encode(password);

  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");

  return hashHex; // ej: "5e88489..."
}

(async () => {
  // AES "de prueba": en serio, en prod debe ser random y guardada por usuario/sesion.
  const aeskey = "12345678901234567890123456789012"; // 32 chars

  const email = "supertransman@hotmail.com";
  const username = email.split("@")[0];
  const password = "1234";
  const passwordHash = await hashPassword(password);

  console.log("PasswordHash: "+passwordHash)

  //console.log("Registrando:", { email, username, password });

  //const reg = await auth.register({
  //  email,
  //  username,
  //  password,
  //  aeskey
  //});
//
  //console.log("REGISTER DEC:", reg);

  const login = await auth.login({
    emailOrUsername: email,
    password:password,
    aeskey
  });

  console.log("LOGIN DEC:", login);
  setSessionFromDecoded(login)
})();
