
import json
import sys
import uuid
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def base64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def pem_to_jwk(pem_file):
    with open(pem_file, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    if not isinstance(public_key, rsa.RSAPublicKey):
        raise ValueError("Only RSA public keys are supported")

    numbers = public_key.public_numbers()

    modulus = numbers.n.to_bytes(
        (numbers.n.bit_length() + 7) // 8, "big"
    )
    exponent = numbers.e.to_bytes(
        (numbers.e.bit_length() + 7) // 8, "big"
    )

    jwk = {
        "kty": "RSA",
        "use": "enc",
        "alg": "RSA-OAEP-256",
        "kid": str(uuid.uuid4()),
        "n": base64url_encode(modulus),
        "e": base64url_encode(exponent)
    }

    return jwk


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python pem_to_jwk.py public_key.pem")
        sys.exit(1)

    jwk = pem_to_jwk(sys.argv[1])
    print(json.dumps(jwk, indent=4))

