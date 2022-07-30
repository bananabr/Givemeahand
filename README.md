## What is this?
A PoC tool to exploit privileged dangling process handles.

## How does it work?
The tool look for high-privilege process handles inherited by low-privilege processes.  If candidates are found, the tool is able to spawn privileged processes by cloning the vulnerable handles.  For more details about the technique, please refer to https://aptw.tf/2022/02/10/leaked-handle-hunting.html.

![](/Give-me-a-hand.gif)

## How to use it?

```
# list only
.\Givemeahand
# try to spawn privileged process
.\Givemeahand --cmd "%windir%\system32\WindowsPowerShell\v1.0\PowerShell_ISE.exe"
```

## Known issues
* I was not able to call OpenProcess on privileged processes even when using **PROCESS_QUERY_LIMITED_INFORMATION** only. Therefore, the tool considers every process handle that we could not map to a PID to be a high-privilege process handle. Because of this approach, false positives are expected.
* For some reason, I could only successfully launch processes with a graphical interface (e.g. PowerShell_ISE.exe, mspaint.exe, etc).  I never took the time to understand why this is the case. **PRs are welcome!**

## Credits
* https://aptw.tf/2022/02/10/leaked-handle-hunting.html
* http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/