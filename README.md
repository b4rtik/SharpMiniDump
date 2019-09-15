# SharpMiniDump

Create a minidump of the LSASS process from memory (Windows 10 - Windows Server 2016). The entire process uses: dynamic API calls, direct syscall and Native API unhooking to evade the AV / EDR detection.

SharpMiniDump is a rough port of this project [Dumpert](https://github.com/outflanknl/Dumpert) by [@Cn33liz](https://twitter.com/Cneelis) and you will find the detail in this [post](https://outflank.nl/blog/2019/06/19/red-team-tactics-combining-direct-system-calls-and-srdi-to-bypass-av-edr/), so BIG credits to him.

Other credits go to [@cobbr_io](https://twitter.com/cobbr_io) and [@TheRealWover](https://twitter.com/TheRealWover) for their work on [SharpSploit](https://github.com/cobbr/SharpSploit) (Execution / DynamicInvoke)


 
