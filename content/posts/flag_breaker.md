---
title: flag breaker writeup
date: 2025-12-01
description: "[rev] writeup of the flag breaker challenge from zeroday ctf 2025 (which I created)"
tags: ["ctf","rev","my challenge"]
---

# Challenge description

```
match the high score and get the flag (guide below):

🟥🟧🟨🟩🟦 HIGH SCORE
🟦🟥🟧🟨🟩 213700
🟩🟦🟥🟧🟨 SCORE
🟨🟩🟦🟥🟧 213700

YOUR FLAG: zerdoday{...}
   🟣

   🟨🟨🟨


ps https://www.mesen.ca/ might be useful.
```

files :


[breakout.sfc](/files/flag_breaker/breakout.sfc)

[breakout.sym](/files/flag_breaker/breakout.sym)


sha256 sums:

```
6ac24d634988d54a5638202682d9e10ebc9ef43f6ab640add2cdc6fcb631055a  breakout.sfc
4a631d8dd125f31285b541d88ad2044e1dc33c1547972b0f0579897727963f5f  breakout.sym
```

12 paritcipants solved this challange out of 86 -> 13.95% solve rate

it was 8th hardest challange out of 25 challanges in the ctf

# Solution


as suggested in the challenge description, we can use the mesen emulator to analyze the game rom

after loading the rom in mesen, we can see that this is snes brakout game

![start](/images/flag_breaker/start.png)


based on the description we need to get a score of 213700 to get the flag, but playing the game normally to get this score is (i think) impossible

we can attach a debugger to the game in mesen, and search for the score variable, by simply searching for string `score` in the disassembly, as we have debug suymbols provided in the challenge files

![score](/images/flag_breaker/score.png)


by adding `score` variable memory address to the `watch` window, or by displaying memory at that address, we can see the score value

![value](/images/flag_breaker/value.png)

here I have score 240, which is 0x18 in memory - so last `0` is skipped and score is stored as `21370` in memory

so to get the flag we need to change the score value in memory to `21370` which is `0x7A53` in hex 

after changing the value in memory, and resuming the game flag appears on screen

![flag](/images/flag_breaker/flag.png)

flag: `zeroday{to_rev_or_to_cheat_that_is_the_question}`
