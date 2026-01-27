// este va a llevar todo el core de la app

// Auth.js
import { AuthService } from "./Services.js";
import { Session,getSessionOrNull,setSessionFromDecoded,clearSession } from "./ModelSession.js"
import "./Env.js"
import { StatefulEnabled } from "./Env.js";

const auth = new AuthService();

export async function login(emailOrUsername, password, aeskey){
  const session = auth.login(emailOrUsername, password, aeskey);
  setSessionFromDecoded(session);
  if (StatefulEnabled){
    // falta iniciar el contador de autorefresh si es stateful
  }
}

export async function register(email, username, password, aeskey){
  const session = auth.register(email, username, password, aeskey);
  setSessionFromDecoded(session);
  if (StatefulEnabled){
    // falta iniciar el contador de autorefresh si es stateful
  }
}

export async function logout(user_id,aes_old,refresh_token){
  // falta decidir cual usar dependiendo de conf en env
  clearSession(getSessionOrNull());
  if (StatefulEnabled){
    console.log("stateful")
    return auth.unloginStateful(user_id,aes_old,refresh_token);
  }
  console.log("stateless")
  return auth.unloginStateless(aes_old,refresh_token);
}

export async function sendStateful(url,data,files){ // puedo pasarlo a esta asi envian facil data:dict y files:binary[]
  // hay que hacer y testear esta
}

export async function sendStateless(url,packet){
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

  alert("wait para ver");

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
    refresh_token: refreshToken
  });
  console.log("REFRESH DEC:", refresh);
  setSessionFromDecoded(refresh)

  session = getSessionOrNull();
  aes = session.aes;
  console.log("aes: "+aes);
  userid = session.user_id;
  acces = session.access_token;
  refreshToken = session.refresh_token;

  const unlog = await logout({
    user_id: userid,
    aes_old: aes,
    refresh_token: refreshToken,
  });
  console.log(unlog);

  clearSession(refresh)

})();
