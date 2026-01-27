// este va a llevar las configuraciones

// url del balanceador
export const AUTH_BASE_URL = "http://localhost:8081"; 

export const StatefulEnabled = true; // sesiones con timer local, y posibilita endpoints de SF
export const StatefulTimeSession=10; // minutos dura cada sesion SF

export const JWTExpires = 3; // minutos
