# InfinityHook
Hook system calls, context switches, page faults and more.

Buried in the Windows kernel for the last decade, InfinityHook is an incredibly subtle and covert mechanism to hook system calls, software context switches and more. InfinityHook is somewhat related to DTRACE showcased by Alex Ionescu, but is much older, does not require the system to be booted in debug mode, works alongside patchguard, and exists from early versions of Windows 7 all the way to 1903.

Is InfinityHook an exploit? Probably, but due to the nature of it needing to be deployed at CPL0, it does not qualify as one. 

Due to its subtle nature, InfinityHook also works underneath VBS, HVCI and Hyperguard. 

InfinityHook stands to be one of the best tools in the rootkit aresenal over the last decade.
