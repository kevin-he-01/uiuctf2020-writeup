#! /usr/bin/env powershell.exe
param(
    [Parameter(Mandatory=$true)][string]$vncinput
)
Add-Type -AssemblyName System.Windows.Forms

Add-Type @"
using System;
using System.Runtime.InteropServices;

namespace sendkeys
{
    public class sendkeys
    {
        // Get a handle to an application window.
        [DllImport("USER32.DLL", CharSet = CharSet.Unicode)]
        public static extern IntPtr FindWindow(string lpClassName,
            string lpWindowName);

        // Activate an application window.
        [DllImport("USER32.DLL")]
        public static extern bool SetForegroundWindow(IntPtr hWnd);
    }
}
"@
$teamPort = "<Team ID>" # Replace with your team ID by looking at your VNC Window's title bar
$windowName = "kernel.chal.uiuc.tf:$teamPort (Team $teamPort) - VNC Viewer" # Must match your VNC's window name
$handle = [sendkeys.sendkeys]::FindWindow("vwr::CDesktopWin", $windowName) # If you are not using RealVNC, replace vwr::CDesktopWin with your window class name
if ($handle -eq 0) {
    throw "Unable to find VNC window. Make sure you edited the script and replaced the Window name correctly"
}

if ([sendkeys.sendkeys]::SetForegroundWindow($handle)) {
    [System.Windows.Forms.SendKeys]::SendWait($vncinput);
    echo "Successfully sent keys"
} else {
    throw "Failed to make VNC the foreground window. Make sure your Windows Powershell session is currently running in the foreground and not inside a terminal emulator."
}
