import jwt, datetime

with open("private.pem", "r") as f:
    private_key = f.read()
with open("public.pem", "r") as f:
    public_key = f.read()

payload = {
    "sub": "user123",
    "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=15)
}

token = jwt.encode(payload, private_key, algorithm="RS256") # acces token
data = jwt.decode(token, public_key, algorithms=["RS256"]) # token check

print("Token:", token)
print("Payload:", data)
