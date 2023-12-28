from jwcrypto import jwk, jwt
import jwt as pyjwt
import json


def get_public_key_from_jwks(jwks, kid):
    for key_data in jwks['keys']:
        if key_data.get('kid') == kid:
            return jwk.JWK(**key_data)
    return None

jwks_file_path = "jwks.json"

with open(jwks_file_path, "r") as jwks_file:
    jwks_data = json.load(jwks_file)

jwt_token_file_path = "jwt_token.jwt"

with open(jwt_token_file_path, "r") as jwt_token_file:
    jwt_token_data = jwt_token_file.read()

try:
    header = pyjwt.get_unverified_header(jwt_token_data)
    kid = header.get('kid')
    algorithm = header.get('alg')

    # Get the corresponding public key from JWKS
    public_key = get_public_key_from_jwks(jwks_data, kid)

    if public_key:
        try:
            # using jwcrypto
            token = jwt.JWT(key=jwt.JWK(**public_key), jwt=jwt_token_data, algs=[algorithm])
            # using pyjwt
            decoded_token = pyjwt.decode(jwt=jwt_token_data, key=public_key.export_to_pem(), algorithms=[algorithm])
            print(decoded_token)
            print("Token verified successfully.")

        except Exception as e:
            print(f"Verification error: {str(e)}")
    else:
        print(f"Public key for kid '{kid}' not found in JWKS.")
except pyjwt.ExpiredSignatureError:
    print("Token has expired.")
except pyjwt.InvalidTokenError as e:
    print(f"Invalid token: {str(e)}")
except Exception as e:
    print(f"Error: {str(e)}")



