from jwcrypto import jwk, jwt
import jwt as pyjwt
from jwcrypto.common import json_encode
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import json

with open("private_key.pem", "rb") as f:
    private_key_pem = f.read()

# private_key = serialization.load_pem_private_key(
#     private_key_pem,
#     password=None,
#     backend=default_backend()
# )

# public_key = private_key.public_key()
jwk_private = jwk.JWK.from_pem(private_key_pem)
jwk_public = jwk_private.export(private_key=False)

jwk_public_data = json.loads(jwk_public)
jwks = {
    "keys": [jwk_public_data]
}

print(jwks)

with open("jwks.json", "w") as jwks_file:
    jwks_file.write(json.dumps(jwks))

# Create a JWT Token using the Private Key
payload = {"user_id": 123, "username": "example_user"}
header = {"alg": "RS256", "kid": jwk_public_data["kid"], "typ": "JWT", "kty": "RSA"}

token = jwt.JWT(header=header, claims=payload)
token.make_signed_token(jwk_private)

# Save the JWT Token to a file (for demonstration purposes)
with open("jwt_token.jwt", "w") as jwt_file:
    jwt_file.write(token.serialize())

print("Generated JWT Token:", token.serialize())
