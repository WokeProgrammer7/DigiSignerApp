from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates

data = open("test-signer.p12","rb").read()
priv, cert, others = load_key_and_certificates(data, b"Sample123")
print("Private key found?", bool(priv))
print("Cert subject:", cert.subject if cert else "None")
