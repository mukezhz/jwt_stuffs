import jwt

with open("private_key.pem", "rb") as f:
    private_key_pem = f.read()

with open("public_key.pem", "rb") as f:
    public_key_pem = f.read()


payload = {"user_id": 123, "username": "example_user"}
jwt_token = jwt.encode(payload, private_key_pem, algorithm="RS256")

print("Generated JWT Token:", jwt_token)

try:
    decoded_payload = jwt.decode(jwt_token, public_key_pem, algorithms=["RS256"])
    print("Decoded Payload:", decoded_payload)
except jwt.ExpiredSignatureError:
    print("Token has expired.")
except jwt.InvalidTokenError as e:
    print(f"Invalid token: {str(e)}")