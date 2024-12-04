import binascii, os

print(binascii.hexlify(os.urandom(24)))