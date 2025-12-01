---
title: vibe coding writeup
date: 2025-12-01
description: "[misc] writeup of the vibe coding challenge from zeroday ctf 2025 (which I created)"
tags: ["ctf","misc","my challenge"]
---

# Challenge description

[https://gemini.google.com/share/fe4fdfc523f4](https://gemini.google.com/share/fe4fdfc523f4)

(yes entire challange was generated as 'secure' python code by gemini, and same code was on the server, except with different flag)

# Solution

generated code looks 'secure'

```python
import sys

# Flag stored here
secret = "zeroday{fake_flag}"

# Blacklist setup
BLACKLIST = ["secret", "()", "[", "]", "{", "}", "'", '"', "import", "os", "globals", "locals", "_", "getattr", "dir", "eval", "exec", "system"]
MAX_LEN = 6

print("Welcome to the 6-character Python jail!")

while True:
    try:
        user_input = input(">>> ").strip()
        
        # Check 1: Length
        if len(user_input) > MAX_LEN:
            print("Too long! Max length is 6.")
            continue
            
        # Check 2: Blacklist
        if any(b in user_input for b in BLACKLIST):
            print("Blacklisted character or keyword detected.")
            continue
            
        # Check 3: Empty
        if not user_input:
            continue

        # The dangerous part (but restricted)
        result = eval(user_input)
        print(f"Result: {result}")

    except Exception as e:
        print(f"Error: {e}")
```

to solve the challenge, we need to bypass the restrictions (length and blocked words) and access the `secret` variable

strings with weird characters can be used to bypass the string comparison, for example

```python
>>> secret = "flag"
>>> a = "𝔰𝔢𝔠𝔯𝔢𝔱"
>>> b = "secret"
>>> a == b
False
>>> eval(a)
'flag'
>>> eval(b)
'flag'
>>>
```

so just passing `𝔰𝔢𝔠𝔯𝔢𝔱` or `𝓼𝓮𝓬𝓻𝓮𝓽` will print out `secret` variable

text like that can be genereted on [https://lingojam.com/WeirdTextGenerator](https://lingojam.com/WeirdTextGenerator)

flag on the remote was `zeroday{hmmmmmmmmmmmmmmm_goth_or_latina?}` ;)

