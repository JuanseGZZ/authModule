libreria front:
+ modo stateless:
- ciframos payload con clave AES random{
    guardamos esa clave hasta que llegue la respuesta y luego la cambiamos.
}
- ciframos clave con publica RSA del server.
*funciones:
--cifradoStateless 

+ modo statefull:
- hacemos handshake
- hacemos rotacion de claves cada 15 min
- ciframos paquetes 


libreria back:
+ modo stateless:

+ modo statefull:
