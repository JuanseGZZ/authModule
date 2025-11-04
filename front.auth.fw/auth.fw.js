let url = "http://localhost:8000";

const login = async (username, password) => {
  const res = await fetch(url+"/auth/login", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Accept": "application/json",
      "X-Request-Id": crypto.randomUUID(),  // útil para trazas
      "User-Agent": "WebClient/1.0"         // opcional
    },
    body: JSON.stringify({
      username,
      password
    }),
    credentials: "include"  // si querés cookies httpOnly
  });

  if (!res.ok) throw new Error(`Error ${res.status}`);
  const data = await res.json();
  console.log("Tokens:", data);
  return data; // { access_token, refresh_token, expires_in, ... }
};
