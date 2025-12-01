---
title: mov it mov it 2 (nothing ever happens) writeup
date: 2025-12-01
description: "[rev] writeup of the mov it mov it 2 challenge from zeroday ctf 2025 (which I created)"
tags: ["ctf","rev","my challenge"]
---

# Challenge description

![well](/images/mov_it_mov_it_2/well.png)

files :

[chall](/files/mov_it_mov_it_2/chall)


source code, if you prefer to compile it yourself with movuscator:
[chall.c](/files/mov_it_mov_it_2/chall.c)

sha256 sums:

```
7523e518c6bb4301a8bd01ac3802739664ec81b60a6606a46b8485c425da59d0  chall
6a27b107b1526e1de476e6dde080c9dea44c2bd5f77238e9402b2a7ba79e7220  chall.c
```

7 participants solved this challenge out of 86 → 8.14% solve rate

It was the 2nd hardest challenge out of 25 challenges in the CTF

# Solution

looking at the binary in disassembler we can see that it is quite unreadable

![ida](/images/mov_it_mov_it_2/ida.png)

but looking at the strace we can see that when entering correct input `clock_nanosleep` is called

wrong input (letter `a`):

```
read(0, a
"a\n", 34)                      = 2
write(1, "Wrong!\n", 7Wrong!
)                 = 7
```

correct input (letter `z` - flag format starts with `zeroday{`):

```
read(0, z
"z\n", 34)                      = 2
clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=0, tv_nsec=100000000}, 0x85f70f4) = 0
write(1, "Wrong!\n", 7Wrong!
)          
```

so we can assume that the if the program encounters a letter that is in the flag it will call `clock_nanosleep` (or `usleep` which is visible in the binary imports)

```
# objdump -t chall | grep usleep
00000000       F *UND*  00000000              usleep@GLIBC_2.0
```

this can be verfied by testing with `time` command

```
# echo -n "zerox" | time ./chall
┏┓┳┓┏┳┓┏┓┳┓  ┏┳┓┓┏┏┓  ┏┓┓ ┏┓┏┓
┣ ┃┃ ┃ ┣ ┣┫   ┃ ┣┫┣   ┣ ┃ ┣┫┃┓•
┗┛┛┗ ┻ ┗┛┛┗   ┻ ┛┗┗┛  ┻ ┗┛┛┗┗┛•

Wrong!
Command exited with non-zero status 1
0.00user 0.00system 0:00.47elapsed 0%CPU (0avgtext+0avgdata 2140maxresident)k
2696inputs+0outputs (13major+67minor)pagefaults 0swaps
```

time of execution is `0:00.47` with letter `x` which is not in the flag

```
# echo -n "zerod" | time ./chall
┏┓┳┓┏┳┓┏┓┳┓  ┏┳┓┓┏┏┓  ┏┓┓ ┏┓┏┓
┣ ┃┃ ┃ ┣ ┣┫   ┃ ┣┫┣   ┣ ┃ ┣┫┃┓•
┗┛┛┗ ┻ ┗┛┛┗   ┻ ┛┗┗┛  ┻ ┗┛┛┗┗┛•

Wrong!
Command exited with non-zero status 1
0.00user 0.00system 0:00.59elapsed 0%CPU (0avgtext+0avgdata 2196maxresident)k
2952inputs+0outputs (15major+65minor)pagefaults 0swaps
```

time of execution is `0:00.59` with letter `d` which is in the flag


so by measuring time of execution we can bruteforce the flag letter by letter

solve script:

```python
#!/usr/bin/env python3

import subprocess
import time
import statistics
from concurrent.futures import ThreadPoolExecutor, as_completed

BINARY = "./chall"
FLAG_LENGTH = 33 # strace shows 34 bytes read
RUNS_PER_CHAR = 3
MAX_WORKERS = 40

def time_attempt(guess):
    start = time.perf_counter()
    try:
        proc = subprocess.Popen(
            [BINARY],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        proc.communicate(input=(guess + '\n').encode(), timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        return 999
    end = time.perf_counter()
    return end - start

def test_character(char, known_flag, position):
    test_input = known_flag + char + 'A' * (FLAG_LENGTH - position - 1)

    times = []
    for _ in range(RUNS_PER_CHAR):
        t = time_attempt(test_input)
        times.append(t)

    median_time = statistics.median(times)
    return (char, median_time)

def find_next_char(known_flag):
    position = len(known_flag)
    print(f"\n{'='*60}")
    print(f"position {position}")
    print('='*60)

    chars = "abcdefghijklmnopqrstuvwxyz0123456789_{!}"
    results = {}

    start_time = time.time()
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_char = {
            executor.submit(test_character, char, known_flag, position): char
            for char in chars
        }

        for future in as_completed(future_to_char):
            char, median_time = future.result()
            results[char] = median_time
            #print(f"  '{char}': {median_time*1000:6.1f}ms")

    elapsed = time.time() - start_time

    sorted_chars = sorted(results.items(), key=lambda x: x[1], reverse=True)

    #print(f"\n{'='*60}")
    print(f"tested {len(chars)} chars in {elapsed:.1f}s")
    print("top 5 slowest:")
    for i, (char, t) in enumerate(sorted_chars[:5]):
        marker = " <-- SELECTED" if i == 0 else ""
        print(f"  {i+1}. '{char}': {t*1000:.1f}ms{marker}")

    return sorted_chars[0][0]

def main():
    print(f"workers: {MAX_WORKERS} | runs per char: {RUNS_PER_CHAR}")
    print("="*60)

    flag = "zeroday{"
    print(f"\n[+] flag prefix: {flag}")

    start_time = time.time()

    while len(flag) < FLAG_LENGTH:
        next_char = find_next_char(flag)
        flag += next_char

        elapsed = time.time() - start_time
        print(f"\ncurrent flag: {flag}")
        print(f"progress: {len(flag)}/{FLAG_LENGTH} ({elapsed:.1f}s total)")

        if flag.endswith('}'):
            break

    elapsed = time.time() - start_time
    print("\n" + "="*60)
    print(f"flag: {flag}")
    print(f"total time: {elapsed:.1f}s ({elapsed/60:.1f}min)")
    print("="*60)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted")
```

and its output:


```
./solve_multi.py
workers: 40 | runs per char: 3
============================================================      

[+] flag prefix: zeroday{

============================================================      
position 8
============================================================      
tested 40 chars in 2.8s
top 5 slowest:
  1. 's': 913.5ms <-- SELECTED
  2. '4': 818.2ms
  3. '7': 818.0ms
  4. 'v': 817.8ms
  5. '2': 817.4ms

current flag: zeroday{s
progress: 9/33 (2.8s total)

============================================================      
position 9
============================================================      
tested 40 chars in 3.1s
top 5 slowest:
  1. '0': 1012.4ms <-- SELECTED
  2. 'm': 940.2ms
  3. 'k': 927.8ms
  4. '7': 927.6ms
  5. '1': 927.3ms

current flag: zeroday{s0
progress: 10/33 (5.9s total)

[trunkated]

============================================================      
position 32
============================================================      
tested 40 chars in 9.3s
top 5 slowest:
  1. '}': 3327.4ms <-- SELECTED
  2. 'v': 3255.9ms
  3. 'w': 3254.7ms
  4. 'g': 3253.6ms
  5. 'k': 3251.8ms

current flag: zeroday{s0m3th1ng_h4ppen3d_1!11!}
progress: 33/33 (156.8s total)

============================================================      
flag: zeroday{s0m3th1ng_h4ppen3d_1!11!}
total time: 156.8s (2.6min)
============================================================ 
```