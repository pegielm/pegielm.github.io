---
title: mov it mov it writeup
date: 2024-12-03
description: "writeup of the mov it mov it challenge from zeroday ctf (which I created)"
tags: ["ctf","rev","zeroday"]
---

# Challenge description

Oh no! The poor mage has stumbled upon a massive stone blocking his path. If only there was someone who knew a spell to [mov it](https://www.youtube.com/watch?v=jLPYnw17GTY)...

files :

[chall](/files/mov_it_mov_it/chall)

or you can build it from source:

[source.c](/files/mov_it_mov_it/source.c)

but you need to compile it with [movuscator](https://github.com/xoreaxeaxeax/movfuscator) :)

```bash
movcc  -Wf--no-mov-flow source.c -o chall
```

# Solution


1. run chall in gdb

2. set breakpoint on puts (b *puts) (other breakpoints probably also work, puts is visible in the debugger)

3. stack:

```
───────────────────────────────────────────────────────[ STACK ]────────────────────────────────────────────────────────
00:0000│ eax esp 0x85f626c (stack+2096572) —▸ 0x804b9d0 (main+9972) ◂— mov dword ptr [0x804d370], eax
01:0004│         0x85f6270 (stack+2096576) —▸ 0x804d1e0 ◂— imul esp, dword ptr [eax], 0x746e6163 /* 0x61632069; "i cant't move it move it :(\n" */
02:0008│         0x85f6274 (stack+2096580) ◂— 0x7d /* '}' */
03:000c│         0x85f6278 (stack+2096584) ◂— 1
04:0010│         0x85f627c (stack+2096588) ◂— 0x61 /* 'a' */
05:0014│         0x85f6280 (stack+2096592) ◂— 0
```

last char of flag is at 0x85f6274

4.  rwatch *(int *) 0x85f6274

5. read values from watchpoint and convert to char

6. profit

```
zeroday{l00king_4t_m0ving_ch4rs_m4k3s_r0cks_flight_4way}
```

7. solve script:

```python
#use:
#gdb -x solve.py
#input anything
import pwndbg
import pwndbg.commands
import gdb
file = './chall'
address = 0x85f6274
values = []
# function to print flag chars
def print_value(event):
    value = gdb.parse_and_eval(f'*(int *) {address}')
    print(f'Value at address {hex(address)} changed to: {value}')
    values.append(chr(value))
    print(''.join(values))
    gdb.execute("c")

# add watchpoint
gdb.execute(f'rwatch *(int *) {address}')
# add function to event
gdb.events.stop.connect(print_value)
# gdb commands
gdb.execute(f'file ./{file}')
gdb.execute('run')
gdb.execute('c')
gdb.execute('c')
```

```
┳┳┓┏┓┓┏  ┳┏┳┓  ┳┳┓┏┓┓┏  ┳┏┳┓  ╻
┃┃┃┃┃┃┃  ┃ ┃   ┃┃┃┃┃┃┃  ┃ ┃   ┃
┛ ┗┗┛┗┛  ┻ ┻   ┛ ┗┗┛┗┛  ┻ ┻   •

OH NO ! there is a boulder on the road !
i need a spell that will help me to move it:
zeroday{l00king_4t_m0ving_ch4rs_m4k3s_r0cks_flight_4way}
thank you for helping me!
now i can continue my journey :)
```