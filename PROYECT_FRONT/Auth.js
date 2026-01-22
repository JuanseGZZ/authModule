// este va a llevar todo el core de la app


import { AuthService } from "./Services.js";

const RSA_PUB_PEM = `-----BEGIN PUBLIC KEY-----
...pegas aca la public key del server...
-----END PUBLIC KEY-----`;

const auth = new AuthService({ rsaPublicKeyPem: RSA_PUB_PEM });

(async () => {
  const aeskey = "mi_aes_key_del_user";

  const login = await auth.login({
    emailOrUsername: "test@test.com",
    password: "1234",
    aeskey
  });

  console.log("LOGIN DEC:", login);

  // si es stateful: user_id != "0" y aes_old = aeskey guardada en sesion
  // si es stateless: user_id "0" y aeskey la tenes vos
})();
