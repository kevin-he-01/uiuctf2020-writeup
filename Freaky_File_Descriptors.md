# How a buggy program solves a 400 point challenge
**Writeup Author:** Kevin He (Username `trinary-exploitation`)  
**Category:** Kernel Exploitation
> ### Freaky_File_Descriptors
> How does the OS know what bytes to give you when you call read? How does it keep track of how far you've read into a file?
> 
> Find an exploit that lets you read past the end of /sandb0x/freaky_fds.txt and see what was truncated!

To start, I ran `cat /sandb0x/freaky_fds.txt` to see if the file is suspicious, I get:
> TBD

- ran the program (buggy without close)
- ran it again with minor modifications, like using `0x5f` or underscores to initialize a 500 char buffer.
- now it get the flag
- create superstition/myth that initializing buffer helps
    - unlikely due to `C3` padding already there
    - even called contest manager and got "Small Oops" done
        - initially can't repro
- later use scientific method/experiment
    - control group: ran the same program twice
        - no difference, got flag again
        - make me suspicious
    - realized that I didn't call close -> oops
    - called close, now running twice won't repro -> conclusion: buggy code causes getting flag

## End Notes
There are 13 solves to this 400 point challenge, which is quite surprising. Even the contest managers imaged that people might be utilizing a bug that would qualify as a Small Oops. My guess is that most people wrote a buggy program that doesn't properly close a file descriptor like mine and ran it again in the same `binexec` session after making unnecessary modifications. So future CTF makers have to be careful in designing problems that is difficult to solve not only by valid programs but also by buggy programs. They have to take bugs into account.
