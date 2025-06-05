---
title: fifology writeup
date: 2024-12-03
description: "writeup of the fifology challenge from zeroday ctf (which I created)"
tags: ["ctf","rev"]
---

# Challenge description

In the age of old, before the Stack-mages seized dominion over enchanted devices, only a select few possessed the wisdom to unravel the mysteries of the arcane queue language.

files : 

[program.fo](/files/fifology/program.txt) 

[documentation.md](/files/fifology/documentation.txt)

# Solution

we can seperate the code into parts:
```ASM
PUSH 0;
PUSH 6;
PUSH 102;
PUSH 108;
PUSH 97;
PUSH 103;
PUSH 58;
PUSH 32;
SYSCALL;
```
prints `flag: `
```ASM
PUSH 244;
PUSH 100;
PUSH 224;
PUSH 108;
PUSH 192;
PUSH 92;
PUSH 230;
PUSH 116;
PUSH 202;
PUSH 43;
PUSH 210;
PUSH 105;
PUSH 178;
PUSH 101;
PUSH 162;
PUSH 13;
PUSH 37;
PUSH 78;
PUSH 182;
PUSH 78;
PUSH 166;
PUSH 84;
PUSH 154;
PUSH 72;
PUSH 168;
PUSH 72;
PUSH 168;
PUSH 76;
PUSH 178;
PUSH 68;
PUSH 146;
PUSH 70;
PUSH 166;
PUSH 92;
PUSH 0;
PUSH 34;
``` 
this part of the code is a flag chars before decryption.
```ASM
MOV A 0;  // index
POP B;    // take the flag char into B
CMP B 13; // if flag char == 13...
JNZ 50;
MOV B 33; // ...replace it with 33
CMP B 37; // if flag char == 37...
JNZ 53;   
MOV B 172; // ...replace it with 172
MOV C A;  // C = index
CMP C 0;  // (loop2 start)if index == 0
JZ 60;   //go to DIV B 2
CMP C 1; // if index == 1
JZ 61;  //go to ADD B A
SUB C 2; // index -= 2
JMP 54; //loop2
DIV B 2; //happens if index == 0
ADD B A; // index is added to flag char
PUSH B; // add the flag char to the stack
CMP A 33; // if index == 33
JZ 67;    //break
ADD A 1;
JMP 46;
SYSCALL; //print flag
END 
```
this is loop that iterates over the len of flag (34) and adds index of char to the char itself.
then if index is divisible by 2, it divides the char by 2.

solve script:
```python
n = [244,100,224,108,192,92,230,116,202,43,210,105,178,101,162,13,37,78,182,78,166,84,154,72,168,72,168,76,178,68,146,70,166,92]
n[n.index(13)] = 33
n[n.index(37)] = 172
flag = [ chr((n[i]//2)+i) if i%2==0 else chr(n[i]+i) for i in range(len(n))]
print(''.join(flag))
```

output:
```
zeroday{m4ster_0f_magic_languages}
```

also i wrote interpreter for FIFO-ASM, you can run your challenge with it :)

you can find it here [interpreter.py](/files/fifology/interpreter.py) run with:
```
python3 interpreter.py --file program.fo
```

or

```
python3 interpreter.py --debug --file program.fo
```
