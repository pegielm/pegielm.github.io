---
title: apples and oranges writeup
date: 2025-04-12
description: "[misc] writeup of the apples and oranges challenge from 1753ctf"
tags: ["ctf","misc"]
---

# Challenge description

After capturing an enemy spy, the only thing we got from him was that the password is `bananafruit`. It does not seem to be right though. Can you help us?

`nc apples-and-oranges-25b1895e82ba.tcp.1753ctf.com 12827`

# Solution

after conecting to the server we are presented with following:

```
# nc apples-and-oranges-25b1895e82ba.tcp.1753ctf.com 12827
Wir usen Node v23.10.0
Gib mich eine kleine password:abcdef
abcdef
Well, well, well... das input ist unallowed!
```

so i tried to fuzz the input with following code and see what happens, then i started filtering by error types.

```python
from pwn import *
addr = "apples-and-oranges-25b1895e82ba.tcp.1753ctf.com"
port = "12827"
avalible = ""
for i in range(0,256):
    io = remote(addr, port,level = "error")
    io.recvuntil(b"password:")
    log.success(f"Trying byte: {i}")
    byte = p8(i)
    io.sendline(byte)
    resp = io.recvline(timeout=1)
    status = io.recvline(timeout=1)
    log.success(f"{resp}")
    log.success(f"{status}")
    if b'SyntaxError' in status:
        avalible += byte.decode()
    io.close()
log.success(f"aval: {avalible}")
```

example output:
```
[+] Trying byte: 32
[+] b'\x1b[31G \r\r\n'
[+] b"Nein! TypeError: Cannot read properties of undefined (reading 'toString')\r\n"
[+] Trying byte: 33
[+] b'\x1b[31G!\r\r\n'
[+] b'Nein! SyntaxError: Unexpected end of input\r\n'
[+] Trying byte: 34
[+] b'\x1b[31G"\r\r\n'
[+] b'Well, well, well... das input ist unallowed!\r\n'
```

bytes that gave `SyntaxError`:

```
[+] aval: !()+[]{}
```

So program is using Node js and accepts only !()[]{}, after searching for brackets in js i found https://jsfuck.com/ - a way to encode js code using only !()[]{}, so i used encoder on website to encode `bananafruit` and got following code:

```javascript
([][(!![]+[])[!+[]+!+[]+!+[]]+([][[]]+[])[+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(!![]+[])[!+[]+!+[]+!+[]]+(![]+[])[!+[]+!+[]+!+[]]]()+[])[!+[]+!+[]]+(![]+[])[+!+[]]+([][[]]+[])[+!+[]]+(![]+[])[+!+[]]+([][[]]+[])[+!+[]]+(![]+[])[+!+[]]+(![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(!![]+[])[+[]]
```
but it was too long

```
# nc apples-and-oranges-25b1895e82ba.tcp.1753ctf.com 12827
Wir usen Node v23.10.0
Gib mich eine kleine password:([][(!![]+[])[!+[]+!+[]+!+[]]+([][[]]+[])[+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(!![]+[])[!+[]+!+[]+!+[]]+(![]+[])[!+[]+!+[]+!+[]]]()+[])[!+[]+!+[]]+(![]+[])[+!+[]]+([][[]]+[])[+!+[]]+(![]+[])[+!+[]]+([][[]]+[])[+!+[]]+(![]+[])[+!+[]]+(![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(!![]+[])[+[]]
([][(!![]+[])[!+[]+!+[]+!+[]]+([][[]]+[])[+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(!![]+[])[!+[]+!+[]+!+[]]+(![]+[])[!+[]+!+[]+!+[]]]()+[])[!+[]+!+[]]+(![]+[])[+!+[]]+([][[]]+[])[+!+[]]+(![]+[])[+!+[]]+([][[]]+[])[+!+[]]+(![]+[])[+!+[]]+(![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(!![]+[])[+[]]
Deine password ist too lange! Try einmal!
```

so i used following script to check max length of input:

```python
from pwn import *
addr = "apples-and-oranges-25b1895e82ba.tcp.1753ctf.com"
port = "12827"
for i in range(1,256):
    io = remote(addr, port,level = "error")
    io.recvuntil(b"password:")
    log.success(f"Trying len: {i+2}")
    payload = b"!"* i + b"[]"
    io.sendline(payload)
    resp = io.recvline(timeout=1)
    status = io.recvline(timeout=1)
    log.success(f"{resp}")
    log.success(f"{status}")
```

output:

```
[+] Trying len: 184
[+] b'\x1b[31G!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!![]\r\r\n'
[+] b'Password true nicht korrekt!\r\n'
[+] Trying len: 185
[+] b'\x1b[31G!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!![]\r\r\n'
[+] b'Deine password ist too lange! Try einmal!\r\n'
```

length of previous payload was 354 and maximum is 184, to bypass this i split the payload into 3 parts:

ba + nan + fruit

```javascript
ba -> ({}+[])[+!+[]+!+[]]+(![]+[])[+!+[]]
nan (like in not a number) -> (+[![]]+[])
afruit -> (![]+[])[+!+[]]+(![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(!![]+[])[+[]]
```

final payload with length of 154 (you can try running it in a browser console :)
```javascript
({}+[])[+!+[]+!+[]]+(![]+[])[+!+[]]+(+[![]]+[])+(![]+[])[+!+[]]+(![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(!![]+[])[+[]]
```

and solve:

```
# nc apples-and-oranges-25b1895e82ba.tcp.1753ctf.com 12827
Wir usen Node v23.10.0
Gib mich eine kleine password:({}+[])[+!+[]+!+[]]+(![]+[])[+!+[]]+(+[![]]+[])+(![]+[])[+!+[]]+(![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(!![]+[])[+[]]
({}+[])[+!+[]+!+[]]+(![]+[])[+!+[]]+(+[![]]+[])+(![]+[])[+!+[]]+(![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(!![]+[])[+[]]
Oooooh, flag ist 1753c{b4n4n4_1s_g00d_s0urc3_0f_pot4ss1um}
```
