---
title: invaders writeup
date: 2025-06-01
description: "writeup of the invaders challenge from nops ctf 2025"
tags: ["ctf","rev"]
---

# Challenge description

We've found an old-school space-invaders game on a PwnTopia server, but it seems to be unusually large in size. Maybe something is hidden inside of it...


# Solution

we are given binary file (game):

![game](/images/invaders/invaders_game.png)

first we can see that this is Godot Engine game, so we can extract the game - for example using [Godot RE Tools](https://github.com/GDRETools/gdsdecomp)

after opening the game in Godot there is suspicious fragment of code: 

![godot](/images/invaders/invaders_godot.png)


which creates a file from hex array. GDScript is similar to Python, so we can easily replicate this and get obfuscated file:

```python
f = [7, 53, 218, 111, 73, 111, 74, 111, 78, 111, 74, 111, 181, 144, 74, 111, 242
########## TRUNCATED ############
74, 111, 74, 111, 74, 111, 74, 111, 74, 111, 74, 111, 74, 111, 74, 111]
e = [74, 111, 74, 111]
v = []

for w in range(len(f)):
    v.append(f[w] ^ e[w % len(e)])
with open('out.exe', 'wb') as l:
    l.write(bytearray(v))
    l.close()
```

out.exe is a windows executable:

```
> .\out.exe

      .-"""-.
     / .===. \
     \/ 0 0 \/
     ( \_-_/ )
 ___ooo__V__ooo___
|                |
|  Espeax wants  |
|   to escape!   |
|________________|


Espeax, a brave inhabitant of N0PStopia, has been captured and trapped within a cryptic binary by the sinister agents of PWNtopia.
There is only one way out -- the right key must be found, hidden somewhere in the environment.

To escape provide me the right key...
```

we can't send any input to the program, so let's inspect the binary in IDA.

![invaders_main](/images/invaders/invaders_main.png)



there happens some decryption of the Format variable, which can be reversed

```python
data = [
    0x87, 0x13, 0xEE, 0x13, 0x26, 0x03, 0xEA, 0x26, 0xC2, 0xFA,
    0xD2, 0xEE, 0x26, 0x1F, 0xF6, 0x23, 0x1B, 0xCF, 0x26, 0x7F,
    0xE7, 0x67, 0x6B, 0xCA, 0x12, 0xEA, 0x12, 0xEA, 0xB2
]

def rol8(x, n):
    return ((x << n) & 0xFF) | (x >> (8 - n))

def ror8(x, n):
    return (x >> n) | ((x << (8 - n)) & 0xFF)

decoded_bytes = []
for b in data:
    tmp1 = ror8(b, 1)
    tmp2 = (tmp1 - 49) & 0xFF
    tmp3 = ror8(tmp2, 3)
    tmp4 = (100 - tmp3) & 0xFF
    bout = rol8(tmp4, 2)
    decoded_bytes.append(bout)

format_str = bytes(decoded_bytes).decode('ascii')
print(format_str)
```
Output:
```
Here is your flag: N0PS{%s%s}
```
so that is where flag is printed - it is constructed from two strings: pbData and unk_140005740

by examining xrefs to pbData we can find that it is used in StartAddress function:

![invaders_pbdata](/images/invaders/invaders_pbdata.png)

and is decoded by adding index of byte to the byte itself:

![invaders_start_address](/images/invaders/invaders_start_address.png)

```python
data = [0x59, 0x2F, 0x73, 0x5C, 0x44, 0x2F, 0x70, 0x2C, 0x57]

decoded = ""

for i in range(len(data)):
    decoded += chr(data[i]+i)
print(decoded)
```
Output:
```
Y0u_H4v3_
```

second part of the flag - unk_140005740 is used in sub_140001290:

![invaders_unk](/images/invaders/invaders_unk.png)


sub_140001290 has two interesting parts - first is aR2v0rw52axjvbm variable, which contains a base64 encoded string:

```python
>>> b64decode("R2V0RW52aXJvbm1lbnRWYXJpYWJsZUE=")
b'GetEnvironmentVariableA'
```

this decoded string is passed to GetProcAddress function, which is used to get address of a function in a DLL. In this case it is used to get address of GetEnvironmentVariableA function from kernel32.dll

and then it is used to get environment variable "N0PS_ENV" 

![invaders_sub](/images/invaders/invaders_sub.png)

data pulled from the environment variable is checked against decrypted string:

```python
data = [0xB9, 0x9D, 0x58, 0xBD, 0x9B, 0x37, 0xBD, 0xB9, 0x19, 0x7A, 0x9D, 0x18, 0x23]

def rol8(x, n):
    return ((x << n) & 0xFF) | (x >> (8 - n))

decrypted = []
for b in data:
    tmp = ((-125) - b) & 0xFF
    tmp2 = rol8(tmp, 3) & 0xFF
    new_b = (tmp2 - 3) & 0xFF
    decrypted.append(new_b)

decrypted = bytes(decrypted).decode("ascii")
print(decrypted)
```
Output:
```
S4V3D_3SPE4X
```
we have our flag N0PS{Y0u_H4v3_S4V3D_3SPE4X} but also we can just set environment variable N0PS_ENV to S4V3D_3SPE4X and run the program again:

```
> $env:N0PS_ENV="S4V3D_3SPE4X"
> .\out.exe

      .-"""-.
     / .===. \
     \/ 0 0 \/
     ( \_-_/ )
 ___ooo__V__ooo___
|                |
|  Espeax wants  |
|   to escape!   |
|________________|


Espeax, a brave inhabitant of N0PStopia, has been captured and trapped within a cryptic binary by the sinister agents of PWNtopia.
There is only one way out -- the right key must be found, hidden somewhere in the environment.

To escape provide me the right key...
Here is your flag: N0PS{Y0u_H4v3_S4V3D_3SPE4X}
```





