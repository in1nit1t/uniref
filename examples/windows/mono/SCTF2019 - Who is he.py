from base64 import b64decode
from Crypto.Cipher import DES
from uniref import WinUniRef

# Attachment: examples/bin/Who is he.zip
# 1. Run Who is he.exe
# 2. Run this script & get flag


def solve():
    ref = WinUniRef("Who is he.exe")
    clazz = ref.find_class_in_image("UnityEngine.UmbraModule", "UnityEngine.UmbraModule.Main")

    encrypt_data = clazz.find_field("EncryptData")
    addresses = clazz.guess_instance_address()
    for address in addresses:
        encrypt_data.set_instance(address)
        cipher = encrypt_data.value
        if isinstance(cipher, str) and cipher.startswith("xZ"):
            break
    assert cipher == "xZWDZaKEhWNMCbiGYPBIlY3+arozO9zonwrYLiVL4njSez2RYM2WwsGnsnjCDnHs7N43aFvNE54noSadP9F8eEpvTs5QPG+KL0TDE/40nbU="
    cipher = b64decode(cipher)

    encrypt_key = clazz.find_field("encryptKey")
    key_iv = encrypt_key.value.encode("utf-16")[2:]
    assert key_iv == b"t\x00e\x00s\x00t\x00"

    plain = DES.new(key_iv, DES.MODE_CBC, key_iv)
    flag = plain.decrypt(cipher).decode("utf-16")
    print(flag)


if __name__ == "__main__":
    solve()
