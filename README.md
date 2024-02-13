## What is this?
A PoC tool to exploit privileged dangling handles.

## How does it work?
The tool looks for high-privilege process handles inherited by low-privilege processes.  If candidates are found, the tool is able to spawn privileged processes by cloning the vulnerable handles.  For more details about the technique, please refer to https://aptw.tf/2022/02/10/leaked-handle-hunting.html.

![](/Give-me-a-hand.gif)

## How to use it?
```
# list only
.\Givemeahand --cmd "%windir%\system32\WindowsPowerShell\v1.0\PowerShell_ISE.exe"
```

Here is a target project if you want to test the tool https://github.com/bananabr/VulnHandleSample

## Dependencies
* https://github.com/microsoft/wil

## Credits
* https://aptw.tf/2022/02/10/leaked-handle-hunting.html
* http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/

## TODOS
- [x] exploit for PROCESS_ALL_ACCESS
- [x] exploit for PROCESS_CREATE_PROCESS
- [ ] exploit for PROCESS_CREATE_THREAD
- [ ] exploit for PROCESS_DUP_HANDLE
- [ ] exploit for PROCESS_VM_WRITE
- [ ] exploit for THREAD_ALL_ACCESS
- [ ] exploit for THREAD_DIRECT_IMPERSONATION
- [ ] exploit for THREAD_SET_CONTEXT

**PRs are welcome!**

[!["Buy Me A Coffee"](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/bananabr)
