# UIUCTF 2020 Writeups: pwnyOS privilege escalation series
This repository holds the writeup series that gets you from the sandboxed user running in a `binexec` loop to a full-fledged superuser capable of performing _everything_ on the system except modifying/deleting files or running arbitrary kernel code.

Along the way, I will explain relevant operating system concepts necessary for the exploit. I learned a lot of them by doing these challenges.

Writeups in this series:
1. Whats_A_Syscall?: Logging into the system and escape the infinite `binexec` loop
2. Crazy_Caches: Escape the sandbox and become a normal user named `user`
3. Kernel::Run_it_as_Root: Become the superuser: `root`
