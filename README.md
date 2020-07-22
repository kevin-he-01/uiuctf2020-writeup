# UIUCTF 2020 Writeups: [pwnyOS](https://github.com/sigpwny/pwnyOS-2020-docs) privilege escalation series
This repository holds the writeup series that gets you from the sandboxed user running in a `binexec` loop to a full-fledged superuser capable of performing _everything_ on the system except modifying/deleting files or running arbitrary kernel code.

Along the way, I will explain relevant operating system concepts necessary for the exploit. I learned a lot of them by doing these challenges.

Beginners should start by reading Whats_A_Syscall, and advanced users can jump straight to Crazy_Caches or Kernel::Run_it_as_Root.

Writeups in this series:
1. Whats_A_Syscall? (67 solves, 100 points): Logging into the system and escape the infinite `binexec` loop. Contains basic information needed to understand writeups later in this series.
2. Kernel_Memory_Leak (5 solves, 300 points): _Bonus_: Not privilege escalation related. Not required for the next exploit, but interested people can read this.
3. Crazy_Caches (8 solves, 500 points): Escape the sandbox and become a normal user named `user`
4. [Kernel::Run_it_as_Root](Kernel_Run_As_Root.md) (3 Solves, 666 points): Become the superuser: `root`
