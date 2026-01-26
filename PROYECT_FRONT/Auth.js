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
  // hay que hacer y testear esta
}

export function sendStateless(url,packet){
  // hay que hacer y testear esta
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

  let session = getSessionOrNull();
  let aes = session.aes;
  let userid = session.user_id;
  let acces = session.access_token;
  let refreshToken = session.refresh_token;

  console.log(session);
  console.log(aes);
  

  const refresh = await auth.refreshStateful({
    user_id: userid,
    aes_old: aes,
    refresh_token: refreshToken,
    access_token: acces,
    data: {},
    files: []
  });
  console.log("REFRESH DEC:", refresh);


})();
