---
title: cpu goes brrr writeup
date: 2024-07-05
description: "writeup of the cpu goes brr challenge from hack cert 2024 ctf"
tags: ["ctf","rev","ecsc24"]
---

# Challenge description

[link to challange](https://hack.cert.pl/challenge/brrr)

"It might print the flag. If you wait long enough... https://www.youtube.com/watch?v=h3hwff_CeeM."

# Solution

The challenge is binary file, we can decompile it using Ida (or other disassembler).

These are most important parts of the code:

main function:
```c
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  void *v3; // rsp
  char v4; // r12
  int i; // [rsp+8h] [rbp-30h] BYREF
  int v7; // [rsp+Ch] [rbp-2Ch]
  __int64 v8; // [rsp+10h] [rbp-28h]
  void *s; // [rsp+18h] [rbp-20h]
  unsigned __int64 v10; // [rsp+20h] [rbp-18h]

  v10 = __readfsqword(0x28u);
  v7 = 37;
  v8 = 37LL;
  v3 = alloca(48LL);
  s = &i;
  memset(&i, 0, 38uLL);
  for ( i = 0; i < v7; ++i )
  {
    v4 = byte_4020[i];
    *((_BYTE *)s + i) = sub_126B(i * i * i) ^ v4;
    puts((const char *)s);
  }
  return 0LL;
}
```
key generation function:
```c
__int64 __fastcall sub_126B(unsigned int a1)
{
  unsigned __int16 v2; // [rsp+1Eh] [rbp-12h]
  unsigned int v3; // [rsp+20h] [rbp-10h]
  int i; // [rsp+24h] [rbp-Ch]
  int v5; // [rsp+28h] [rbp-8h]
  int j; // [rsp+2Ch] [rbp-4h]

  v2 = ~(unsigned __int16)sub_1230(a1);
  v3 = 0;
  for ( i = 0; i <= 7; ++i )
  {
    v5 = 0;
    for ( j = 0; j <= 195051540; ++j )
    {
      v5 = ((unsigned __int8)((v2 >> 11) ^ (v2 >> 10) ^ HIBYTE(v2)) ^ (v2 >> 12)) & 1;
      v2 = (v2 >> 1) | ((((unsigned __int8)((v2 >> 11) ^ (v2 >> 10) ^ HIBYTE(v2)) ^ (v2 >> 12)) & 1) << 15);
    }
    v3 = v5 + 2 * v3;
  }
  return v3;
}
```
checking if generated trionacci number is prime, if not generating next one:
```c
__int64 __fastcall sub_1230(unsigned int a1)
{
  __int64 v3; // [rsp+18h] [rbp-8h]

  while ( 1 )
  {
    v3 = sub_1189(a1);
    if ( (unsigned int)sub_11DC(v3) )
      break;
    ++a1;
  }
  return v3;
}
```
is prime number function:
```c
_BOOL8 __fastcall sub_11DC(unsigned __int64 a1)
{
  _BOOL4 v2; // [rsp+Ch] [rbp-Ch]
  unsigned __int64 i; // [rsp+10h] [rbp-8h]

  v2 = a1 > 1;
  for ( i = 2LL; i < a1; ++i )
  {
    if ( !(a1 % i) )
      v2 = 0;
  }
  return v2;
}
```
tribonacci number generation function:
```c
__int64 __fastcall sub_1189(int a1)
{
  __int64 v2; // rbx
  __int64 v3; // rbx

  if ( a1 <= 2 )
    return 1LL;
  v2 = sub_1189((unsigned int)(a1 - 1));
  v3 = sub_1189((unsigned int)(a1 - 2)) + v2;
  return v3 + sub_1189((unsigned int)(a1 - 3));
}
```
contents of byte_4020:
```c
byte_4020       db 6Eh, 68h, 78h, 8, 0B0h, 77h, 45h, 0, 6Fh, 89h, 8Bh
                db 4, 0BCh, 0E8h, 0C2h, 99h, 3Bh, 0DCh, 0Bh, 43h, 4Fh
                db 21h, 72h, 56h, 0C8h, 0DDh, 0E3h, 0E8h, 46h, 0EDh, 94h
                db 0D7h, 6Fh, 5, 1, 0F4h, 0BFh
 _data           ends
```

Then we can recreate program in python and optimize it a bit:
```python
from sympy import isprime

def tribonacci_modified(n):
    if n <= 2:
        return 1
    if n == 3:
        return 3
    n-=1
    a, b, c = 1, 1, 1
    for _ in range(4, n + 1):
        d = (a + b + c)%2**64
        a, b, c = b, c, d
        b = b%2**64
        a = a%2**64
        c = c%2**64
    return c

def next_prime_tribonacci(start):
    while True:
        fib_val = tribonacci_modified(start)
        if isprime(fib_val):
            break
        start += 1
    return fib_val

def gen_key(a1):
    v2 = ~next_prime_tribonacci(a1) & 0xFFFF
    print(v2)
    v3 = 0
    for _ in range(8):
        for _ in range(256):
            v5 = ((v2 >> 11) ^ (v2 >> 10) ^ (v2 >> 8) ^ (v2 >> 12)) & 1
            v2 = ((v2 >> 1) | (v5 << 15)) & 0xFFFF
        v3 = (v5 + 2 * v3) & 0xFFFF
    return v3


def main():
    len = 37
    flag = bytearray(38)
    xor_keys = [
        0x6E, 0x68, 0x78, 0x08, 0xB0, 0x77, 0x45, 0x00, 0x6F, 0x89, 0x8B,
        0x04, 0xBC, 0xE8, 0xC2, 0x99, 0x3B, 0xDC, 0x0B, 0x43, 0x4F,
        0x21, 0x72, 0x56, 0xC8, 0xDD, 0xE3, 0xE8, 0x46, 0xED, 0x94,
        0xD7, 0x6F, 0x05, 0x01, 0xF4, 0xBF
    ]

    for i in range(len):
        flag[i] = gen_key(i * i * i) ^ xor_keys[i]
        print(flag.decode('utf-8', errors='ignore'))
    return 0

main()
```

Program generates tribonacci numbers faster ( with iterative apporach instead of recursive) and uses sympy library to check if number is prime. Then instead of going through loop gazilion times it can run 256 times and have same result.

After running the script we get the flag:
```bash
e
ec
ecs
ecs
ecs
ecs4
ecs4{
ecs4{\
ecs4{\
ecs4{\0
ecs4{\0w
ecs4{\0w_
ecs4{\0w_4
ecs4{\0w_4n
ecs4{\0w_4nd
ecs4{\0w_4nd_
ecs4{\0w_4nd_5
ecs4{\0w_4nd_5t
ecs4{\0w_4nd_5t3
ecs4{\0w_4nd_5t3a
ecs4{\0w_4nd_5t3ad
ecs4{\0w_4nd_5t3ady
ecs4{\0w_4nd_5t3ady_
ecs4{\0w_4nd_5t3ady_w
ecs4{\0w_4nd_5t3ady_w1
ecs4{\0w_4nd_5t3ady_w1n
ecs4{\0w_4nd_5t3ady_w1ns
ecs4{\0w_4nd_5t3ady_w1ns_
ecs4{\0w_4nd_5t3ady_w1ns_t
ecs4{\0w_4nd_5t3ady_w1ns_th
ecs4{\0w_4nd_5t3ady_w1ns_th3
ecs4{\0w_4nd_5t3ady_w1ns_th3_
ecs4{\0w_4nd_5t3ady_w1ns_th3_r
ecs4{\0w_4nd_5t3ady_w1ns_th3_r8
ecs4{\0w_4nd_5t3ady_w1ns_th3_r8c
ecs4{\0w_4nd_5t3ady_w1ns_th3_r8ce
ecs4{\0w_4nd_5t3ady_w1ns_th3_r8ce}
```
The flag is not printed correctly, but we can guess that it is :
```bash
ecs4{sl0w_4nd_5t3ady_w1ns_th3_r8ce}
```

🐢 > 🐇


