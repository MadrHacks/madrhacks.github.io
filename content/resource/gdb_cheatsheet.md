---
title: GDB cheatsheet
date: 2022-11-13
tags: ["pwn", "GDB", "cheatsheet"]
authors:
  - kalex
---


First of all: use [pwndbg](https://github.com/pwndbg/pwndbg)! It has many useful features, which `gef` sometimes misses (don't even think about using `peda`, it's no longer maintained). 
If you already have `gef` installed, clear your `~/.gdbinit` file first (i.e. `rm` it).

## General commands
Here's a list of useful commands (assuming `pwndbg` is used), divided in sections.

### Breakpoints and similar
First of all: whenever the program is running (or waiting for input), you can press ctrl+C to gain control.

- `b function` - sets a breakpoint at the start of [function]
- `b *addr` -  sets a breakpoint at [addr]. The `*` is required by the syntax of GDB
- `b *addr if condition` - conditional breakpoint. Can be used when wishing to execute a loop till a certain point. [Condition] is in the form of `reg|addr == value` (e.g. `$rsi == 0x10` will break when $rsi contains 0x10)
- `catch syscall name` - can be used to stop execution whenever the syscall [name] is being execute (e.g. `catch syscall read` will stop whenever a read syscall is about to be executed). Catch can be used to catch even more stuff, check out documentation if curious
- `del x` - deletes the \[x\]-th breakpoint/catch 
- `del` - deletes every breakpoint/catch previously set

### Inspecting program execution

- `nexti` or `ni` - executes the next assembly instruction. Does **not** follow calls, it just executes them
- `stepi` or `si` - same as ni, but also follows calls
- `c` - continues execution normally

In the rare occasion that you have a binary compiled with `-g` (debug) and its source code, GDB might be able to show the correspondence between source and assembly (roughly). In such occasions, you can use:
- `n` - execute the next line of code.

### Reading memory

- `x[/gx|/wx/s] addr` - print out the address (or its content, depending on the specifier). Every specifier can be prepended by a number (e.g. `20gx`) to print more memory. 
  - `gx` prints a quad word (8 bytes) starting from [addr]
  - `wx` prints a double word (4 bytes) starting from [addr]
  - `s` dereferences [addr] and prints out the pointed string(s) 
- `stack n` - show the first [n] addresses from the stack

### Writing memory

- `set reg=value` - sets register (indicated with `$regname`, e.g. `$rsi`) [reg] to [value]
- `set addr=value` - sets [addr] to [value]. This can be tricky to make it work, as you need to tell the size of the left value. For example, to overwrite an 8-byte word you should use: `set {long}addr=value`. For some reason, the syntax uses curly brackets

### Debugging forking servers
Fork servers can be really annoying to debug, not gonna lie.

A good approach to make debugging ~~kinda~~ sane is the following:
- `set follow-fork-mode child` - makes the debugger follow the child when forking, which is usually what you want
- `set follow-exec-mode same` - makes sure that you keep following the same process (i.e. if the child calls system)
- `set detach-on-fork off` - does **not** detach from the parent process when following the child

Now you are free to:
- set a breakpoint on the function called by the child
- continue till it dies
- use `inferior 1` to return to the parent process, where you can simply continue

### Other useful commands

- `vmmap` - prints mappings of the executing program (i.e. where program in execution, libc, ld, and other libraries live in the virtual memory address space)
- `symbol-file programname` - sometimes `pwninit` will lose the symbols of the program it patches (no idea why). This is not a problem however, as you can use load symbols from [programname] using this command
- `canary` - prints out canaries found on the stack (if any)
- `checksec` - invokes `checksec` directly from GDB
- `cyclic` - invokes `cyclic` directly from GDB
- `nextret` - continues until the next `ret` instruction is found
- `nextcall` - continues until the next `call` instruction is found
- `next...` - type `next` into gdb and press tab. It will tell you what other commands starting with `next` there are
- `telescope addr n` - pretty prints [n] addresses starting from [addr]. Equivalent to `x/n[gx|wx]`, but prettier


### Heap-related commands
Note: this requires that the libc you are using contains debug symbols, otherwise all of these commands will fail miserably.

- `heap` - print all the heap data
- `bins` - prints information of the bins. Other commands can be used to specifically print out specific bins in a more verbose style

I may expand this section in the future, but by the time you'll care about this you'll have already mastered GDB.

### There is much more...
`pwndbg` offers much more. To see all the commands pwndbg adds type `pwndbg` in GDB.


## Still have doubts?
Ask me on discord! :)


## Something's missing? 
Oh... well, I probably forgot to add it. Ping me on Discord, I'll update this.

