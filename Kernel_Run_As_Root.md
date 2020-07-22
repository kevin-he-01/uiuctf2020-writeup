# Exploiting a useless file to perform a useful task
<!-- # How I ran `.gitignore` as `root` -->
**Writeup Author:** Kevin He (Username `trinary-exploitation`)  
**Category:** Kernel Exploitation
> ### Kernel::Run_it_as_Root
> There's a bug with uninitialized memory in the kernel page allocator. Can you find a way to exploit this bug with your new user-level permissions to execute rash as root (UID 0)?
>
> Prerequisite: this challenge requires a UID of 1 to complete, so you need to solve `crazy_caches` first.
>
> Author: ravi

The first step to every Kernel Exploitation challenge is to read the [pwnyOS documentation](https://github.com/sigpwny/pwnyOS-2020-docs). Quoting from the documentation:
> Our intention is that everything you
need to complete these challenges is provided to you- no guessing is involved.

This problem is not an exception. Despite being worth 666 points, careful reading of the documentation and some basic understanding of x86 assembly is all we need to defeat the challenge. With that said, let's see what we can do with our newly gained user privilege:

System calls available to `user` but not for `sandb0x` (with syscall numbers):
- 10 `SWITCH_USER`
- 11 `GET_USER`
- 12 `REMOTE_SETUSER`
- 13 `MMAP`

A lot of those syscalls are related to user management, but elevating to root based solely on those is not practical. They either require the correct root password (`SWITCH_USER` or `su` command) or require existing root privileges (`REMOTE_SETUSER`) in some process on the system. Unlike the previous `Crazy_Caches` challenge, there are no existing processes running as root or UID=0. `lsproc` only reveals `launchd` which is the kernel task that doesn't even have a binary path.

## Discovering a memory allocation bug

This left us with `MMAP`, which requests a 4MB page from the kernel memory allocator, but careful reading of the documentation reveals another reference to this same page allocator in the `EXEC` system call:
> Start a new process- this call won’t exit until the called process calls SYSRET! This syscall returns the exit code the called process sent to SYSRET. Arguments are specified by a space-separated list after the filename. This uses the kernel 4MB page allocator to request a new page for the process.

Since the challenge asks us to find a bug in the kernel memory allocator, these two system calls are going to be the key of our exploit. But before we move on, let's talk about how pwnyOS executable binaries are loaded into memory. Like other operating systems, executables are first loaded into memory from disk before it is executed. Since the kernel need the make sure the memory accessible by one program does not overlap with that of another program (otherwise it would be possible for any process to gain root privilege!), it have to request a currently unused memory page for the process. That is the job of the 4MB page allocator. However, the fact that the page is unused does not mean it is nice and clean with only zeros in it, the kernel seems rather lazy when it comes to memory management: it does not clean up after its processes. Again, quoting from the `EXEC` system call:

> This page may contain program data from previous programs, or from other places the kernel uses the allocator. The new program is read into memory, overwriting the old data. **However, if an old program was larger than the new one, remnants of its memory may still be present in the page!** (You can’t assume all memory is initialized to 0). Returns -1 on failure (cannot execute program). 

I **bolded** the part that is interesting, and I will illustrate it with an example using only ASCII characters and human readable instructions:

Let's say when program A just exited, its memory looks like this:
```
IMPORT 8 TONS OF WHEAT, OUR SOLDIERS ARE STARVING.
```
When program A exits via `SYSRET`, it returns its memory page back to the kernel so that it can reuse it for other purposes. And immediately afterward, program B is launched using an `EXEC` syscall, and content of program B only have 2 bytes, which is:
```
EX
```
When the kernel loads program B's contents into memory, it reuses the just freed page program A and overwrites the first 2 bytes (`IM`) with `EX`, but since the kernel doesn't initialize the entire memory space, the rest of them stays intact, leaving part of program A's memory in program B's:
```
EXPORT 8 TONS OF WHEAT, OUR SOLDIERS ARE STARVING.
```

Due to the nature of ELF format of pwnyOS, if program B behaves correctly, its execution should never depend on memory beyond the end of the executable, and the entry points and exit points are all well-defined addresses that are known to be located inside the executable. But as evident in the line above, loading a seemingly innocent yet malicious program B completely changes the meaning of the sentence: rather than telling you to import wheat, it tells you to export it. The same thing can happen with machine-readable programs, as I will demonstrate in the section below.

## Finding Program A and B on pwnyOS

Now comes the difficult part: how can we find the pair of programs in pwnyOS that allows you to run a program as root? Looking at page 7 of the [Getting Started Guide](https://github.com/sigpwny/pwnyOS-2020-docs/blob/master/Getting_Started.pdf) for pwnyOS titled "pwnyOS **Executables**", I discovered that pwnyOS uses the same executable format as Linux and some other Unix systems: [ELF](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format), but it extends the ELF header to allow privileged binaries similar to the [setuid bit](https://en.wikipedia.org/wiki/Setuid) for Linux executables. While standard ELF files (those found in Linux) starts with these 4 bytes: `7F 45 4C 46`, the first byte of pwnyOS binary can be something other than `7F`: it can be `0x80 + uid` where `uid` specifies the user id of the user it should always be run at (regardless of the current permission of the user running the program, like setuid binaries). For example, a program starting with `82 45 4C 46` would be ran as the `sandb0x` user, whose UID is 2. Therefore, a binary starting with `80 45 4C 46` would always be ran as `root` whose UID is 0.

Sadly, I will tell you that there is no such programs in pwnyOS, and due to the read-only nature of its filesystem, you cannot even create either program, but not all hope are lost. There is indeed an indirect way of achieving basically the same task!