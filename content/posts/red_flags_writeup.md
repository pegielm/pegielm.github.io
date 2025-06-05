---
title: red flags writeup
date: 2024-11-17
description: "writeup of the red flags challenge from block ctf"
tags: ["ctf","rev"]
---
# Challenge description

link to challange : [red flags](https://2024.blockctf.com/challenges#Red%20Flags-18) (34 solves)

The challenge is simple game made in godot engine with a goal to touch flags in correct order - when you touch each flag letters move in some directions.

![game](/images/red_flags/game.png)

We can see bait flag here ;)

# Solution

I started by extracting the game files (project) with [Godot RE Tools](https://github.com/bruvzg/gdsdecomp) and then opened it in godot engine.

![re tools](/images/red_flags/re.png)

Then we can see game source code, also we can debug and change it. In arena.tscn file there is script responsible for calculating letters movement. I added some print statements to extract initial positions of letters and to retreive target positions and hash for debugging of reversed code.

![code](/images/red_flags/code.png)

Output of inital positions - all flags have state '0' (letter(x,y)target_x,target_y):

![initial](/images/red_flags/initial.png)

So to to solve this challange we can bruteforece all possible combinations of touched flags (2**10 - all binary numbers with 10 bits).

Movement of latters is calulated by hashing string of positions with sha1 and md5, extratcing hex string from hashes and concating them with uppercase letters. Then each char is converted to int by hex_to_byte_function. 

These numbers are added to each letter initial position (multiplied by 50). This means that order of touching flags is not important. 

After calulating positions flags are created by sorting letter by x and y and removing digits from keys(they are there only to distinguish duplicates).

Solve script:
    
```python

import string
from hashlib import sha1,md5
def hex_byte_to_int(c):
    c = ord(c)
    if c>= 0x30 and c <= 0x39:
        return c - 0x30
    else:
        return c - 0x37
def sha1_text_upper(text):
    return sha1(text.encode()).hexdigest().upper()
def md5_text_upper(text):
    return md5(text.encode()).hexdigest().upper()
def remove_digits(input_str):
    return input_str.translate(str.maketrans('', '', string.digits))

all = []
for i in range(2**10):
    x = bin(i)[2:]
    x = '0'*(10-len(x))+x
    all.append(x)
flags = []
for c in all:
    char_dict = {
        's0': [-173, -329],
        'l1': [-507, -28],
        '_2': [170, -585],
        'f3': [-172, 18],
        '_4': [-273, -333],
        '}5': [123, -81],
        'e6': [545, -532],
        '{7': [199, -30],
        'a8': [-343, -628],
        'i9': [-74, -478],
        'n10': [64, -380],
        'm11': [187, 69],
        'g12': [77, 123],
        't13': [328, -132],
        'a14': [616, -482],
        's15': [109, -81],
        '_16': [334, -535],
        'e17': [316, -32],
        'o18': [230, -128],
        'm19': [433, -182],
        't20': [5, 71],
        'n21': [-541, -328],
        'i22': [-86, -279],
        '_23': [-109, -534],
        'h24': [-358, -129],
        'o25': [497, -30],
        's26': [-312, -178],
        'w27': [88, -579],
        'w28': [-350, -527],
        'l29': [213, -78]
    }
    #c = '1111111011'
    sha = sha1_text_upper(c)+md5_text_upper(c)
    #print(sha)
    index = 0
    for i in char_dict.keys():
        char_dict[i][0] += (hex_byte_to_int(sha[index*2])-8) *50.0
        char_dict[i][1] += (hex_byte_to_int(sha[index*2+1])-8)*50.0
        index += 1
    #sort by x 
    char_dict = dict(sorted(char_dict.items(), key=lambda item: item[1][0]))
    tmp = remove_digits(''.join(char_dict.keys()))
    flags.append(tmp)
    #sort by y
    char_dict = dict(sorted(char_dict.items(), key=lambda item: item[1][1]))
    tmp = remove_digits(''.join(char_dict.keys()))
    flags.append(tmp)
print('summary')
for f in flags:
    if f.startswith('flag'):
        print(f)

```

Output:

```
flag{now_wishlist_me_on_steam}
```

