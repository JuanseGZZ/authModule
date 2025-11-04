from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# Generar clave privada RSA de 2048 bits
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

# Serializar la clave privada en formato PEM
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

# Obtener la clave pública asociada
public_key = private_key.public_key()

# Serializar la clave pública en formato PEM
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Guardar los archivos
with open("private.pem", "wb") as f:
    f.write(private_pem)

with open("public.pem", "wb") as f:
    f.write(public_pem)

print("✅ Claves generadas correctamente:")
print(" - private.pem (clave privada)")
print(" - public.pem (clave pública)")
