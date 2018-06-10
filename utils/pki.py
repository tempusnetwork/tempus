import hashlib
import binascii
import ecdsa
import base58


# Assuming all input and output is hex (apart from get_kp where input is string)
# Message is always bytes


def get_kp(privkey=None):
    if not privkey:
        sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    else:
        binary_pk = binascii.unhexlify(privkey.encode('ascii'))
        sk = ecdsa.SigningKey.from_string(binary_pk, curve=ecdsa.SECP256k1)
        
    vk = sk.get_verifying_key()
    
    pubkey = tohex(vk.to_string())
    privkey = tohex(sk.to_string())
    
    return [pubkey, privkey]


def pubkey_to_addr(pubkey):
    pubkey = '04' + pubkey  # add tag byte 0x04 (octet string)

    shad_once = hashlib.sha256(binascii.unhexlify(pubkey)).hexdigest()

    h = hashlib.new('ripemd160')
    h.update(binascii.unhexlify(shad_once))

    ripemd = h.hexdigest()
    
    ripemd = '80' + ripemd  # 80 for 't' prepend
    
    shad_twice = hashlib.sha256(binascii.unhexlify(ripemd)).hexdigest()

    shad_thrice = hashlib.sha256(binascii.unhexlify(shad_twice)).hexdigest()

    checksum = shad_thrice[:8]

    binary_addr = ripemd + checksum
    binary_addr = binary_addr.upper()

    to_encode = binascii.unhexlify(binary_addr)
    addr = base58.b58encode(to_encode)

    return addr.decode("utf-8")


def sign(message, privkey):
    binary_pk = binascii.unhexlify(privkey.encode('ascii'))
    sk = ecdsa.SigningKey.from_string(binary_pk, curve=ecdsa.SECP256k1)
    sig = tohex(sk.sign(message))
    return sig


def verify(message, sig, pubkey):
    vk = ecdsa.VerifyingKey.from_string(tobytes(pubkey), curve=ecdsa.SECP256k1)
    verified = vk.verify(tobytes(sig), message)
    return verified


def tohex(b):
    return binascii.hexlify(b).decode('ascii').lower()


def tobytes(h):
    return bytes.fromhex(h)


# TODO: Put in tests folder..
def test():
    privkey = "18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725"
    message = b"hello"
    pubkey = get_kp(privkey)[0]
    print(pubkey_to_addr(pubkey))
    
    signature = sign(message, privkey)
    print("Successfully verified signed message "
          + str(message) + ": " + str(verify(message, signature, pubkey)))
