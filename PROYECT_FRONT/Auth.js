// este va a llevar todo el core de la app

// Auth.js
import { AuthService } from "./Services.js";
import { Session,getSessionOrNull,setSessionFromDecoded,clearSession } from "./ModelSession.js"

const auth = new AuthService();

export function login(emailOrUsername, password, aeskey){
  const session = auth.login(emailOrUsername, password, aeskey);
  setSessionFromDecoded(session);
  // falta iniciar el contador de autorefresh si es stateful
}

export function register(email, username, password, aeskey){
  const session = auth.register(email, username, password, aeskey);
  setSessionFromDecoded(session);
  // falta iniciar el contador de autorefresh si es stateful
}

export function logout(){
  // falta decidir cual usar dependiendo de conf en env
  auth.unloginStateful();
  auth.unloginStateless();
}

export function sendStateful(url,packet){
  // hay que hacer y testear estas
}

export function sendStateless(url,packet){
  // hay que hacer y testear estas
}


/* TESTING */ 
(async () => {
  // AES "de prueba": en serio, en prod debe ser random y guardada por usuario/sesion.
  const aeskey = "12345678901234567890123456789012"; // 32 chars

  const email = "supertransman@hotmail.com";
  const username = email.split("@")[0];
  const password = "1234";

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
