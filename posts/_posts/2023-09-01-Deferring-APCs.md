---
layout: post
title: Deferring APCs
date: 2023-09-01 17:03
categories: [Reverse engineering, Windows, Kernel]
---

# Introduction

In this article, we will be looking at two kernel routines and the impact that they have on the delivery of APCs in KiDeliverApc. The routines in question are KeEnterGuardedRegion and KeEnterCriticalRegion. They are both documented described as, disabling ‘all kernel-mode APC delivery to the current thread’ and disabling ‘the execution of normal kernel APCs, but does not prevent special kernel APCs from running’ (Microsoft), respectively. 

# KeEnterGuardedRegion 

```nasm
mov     rax, gs:188h 
dec     word ptr [rax+1E6h] 
retn
```
As you can see, something is moved into rax from offset 0x188 to the GS segment. This happens to be a pointer to the _KTHREAD structure, detailed here: 
```c
struct _KTHREAD
{
...
     struct
     {
        SHORT KernelApcDisable;                                 //0x1e4
        SHORT SpecialApcDisable;                                //0x1e6
     };
...
}; 
```
The next opcode decrements the memory contents of the address at offset 0x1E6 to _KTHREAD pointer. This happens to be the member, SpecialApcDisable. Changing the value of SpecialApcDisable to a negative value means that normal kernel APCs are disabled for that thread. 

# KeEnterCriticalRegion 

```nasm
mov     rax, gs:188h 
dec     word ptr [rax+1E4h] 
retn 
```
KeEnterCriticalRegion is semantically similar to KeEnterGuardedRegion however the value that is decremented is the KernelApcDisable member. 

# KiDeliverApc

When considering members SpecialApcDisable and KernelApcDisable, we arrive at two places in the code. The first instance, we see the SpecialApcDisable member used is here: 
```nasm
mov     rbx, gs:188h 
... 
cmp     word ptr [rbx+1E6h], 0 
… 
jnz     loc_14020ECA9 
```
Rbx contains a pointer to the _KTHREAD struct and the contents of offset 0x1E6 (SpecialApcDisable) is compared to 0. A conditional jump is then made given that the ZF is 0 given that SpecialApcDisable is not equivalent to 0. If SpeicalApcDisable is 0, then the normal execution flow continues to where the APCs will be delivered. Otherwise, a jump is made to the end of the function. The next place, we see one of the members used is here: 
```nasm
cmp     word ptr [rbx+1E4h], 0 
jz      short loc_14020ED2B 
```
A comparison takes place followed by a conditional jump. In the case that the KernelApcDisable is 0 and no Apc is in progress, a jump is made to a segment where APCs can be delivered otherwise a jump is eventually made to the end of the function. 

Therefore, by using KeEnterGuardedRegion a programmer can delay execution of special APCs on a given thread and by using KeEnterCriticalRegion, a programmer can delay execution of kernel APCs but not special APCs. 

# Conclusion

In this article, I have covered a brief portion of KiDeliverApc, two kernel routines that can be used, and the structures surrounding them. KeEnterCriticalRegion and KeEnterGuardedRegion help programmers avoid pre-emption from APCs allowing atomic operations to occur and interference to be avoided. 