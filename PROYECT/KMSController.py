from userModels import User
from userRepository import userRepository as UR
from KMS import KMS, cifrar_con_user_aes, descifrar_con_user_aes

class KMSController:
    # Update: se debe hacer que se verifique en .env, si KMS_IS_IT_INSTANCE=TRUE, si es asi cifra y decifra en local
    # si es false va a hacer un fetch a KMS_PATH, pidiendole la aes decifrada.
    # NOTA: debe ir cifrada la peticion, asi que es necesario migrar esto a un ksmController.py. DONE
    @staticmethod
    def getDataUncypher(user: User, data: str) -> str | None: # usas para data: user.elDatoADecifrar
        """
        Desencripta un dato del usuario usando la AES privada del usuario.
        - user: objeto de dominio User
        - data: dato cifrado en base64 (ciphertext+IV) que se quiere desencriptar
        Devuelve el dato en claro como str.
        """
        kms = KMS()
        if not data:
            return None
        try:
            # 1) AES en claro descifrada desde user.aesEncriper
            aes_plain_b64 = kms.decifrarKey(user.aesEncriper)

            # 2) Desencriptar el dato usando AES del usuario
            dato_claro = descifrar_con_user_aes(aes_plain_b64, data)

            return dato_claro

        except Exception as e:
            print("Error desencriptando dato:", e)
            return None

    @staticmethod
    def setDataCipher(user:User, data_claro:str): # usas para data: user.elDatoACifrar
        kms = KMS()
        aes = kms.decifrarKey(user.aesEncriper)
        return cifrar_con_user_aes(aes, data_claro)
    
    @staticmethod
    def crearKeyUser():
        return KMS.crearKeyUser()

    @staticmethod
    def decifrarKey(aesEncriped):
        return KMS.decifrarKey(aesEncriped)
