---
layout: post
title: Exploring DPCs
date: 2023-08-30 17:17
categories: [Reverse engineering, Windows, Kernel]
---

# Introduction

Deferred procedure calls (DPCs) are an interrupt-handling mechanism that plays a role in managing system interrupts and maintaining efficient multitasking. A DPC is a function that performs a task that is less critical than the current one, hence the word ‘deferred’ is used to describe these functions as they may not execute immediately. DPCs are commonly used in ISRs as to complete the ISR and continue the servicing of an interrupt after the ISR has finished. 

In this article, I will discuss the various kernel functions and structures surrounding DPCs. 

# KeInitializeDpc 

To begin understanding this function we must first look at the DPC struct. 


```c
struct _KDPC
{
    union
    {
        ULONG TargetInfoAsUlong;                                            //0x0
        struct
        {
            UCHAR Type;                                                     //0x0
            UCHAR Importance;                                               //0x1
            volatile USHORT Number;                                         //0x2
        };
    };
    struct _SINGLE_LIST_ENTRY DpcListEntry;                                 //0x8
    ULONGLONG ProcessorHistory;                                             //0x10
    void (*DeferredRoutine)(struct _KDPC* arg1, void* arg2, void* arg3, void* arg4); //0x18
    void* DeferredContext;                                                  //0x20
    void* SystemArgument1;                                                  //0x28
    void* SystemArgument2;                                                  //0x30
    void* DpcData;                                                          //0x38
}; 
```

Pointers to the DPC object, deferred routine and deferred context are first passed in rcx, rdx and r8 respectively.  
```nasm
mov     dword ptr [rcx], 113h
```
Next, the value 0x113 is moved to base of the struct, TargetInfoAsUlong. Which initializes 3 fields, as shown.

| 00000000 00000000 | 00000001  | 00010011 |
|---------------- | ---------|------- |
| Number            | Importance| Type     |

We can see that the type member takes on the value of 0x13 that comes from the _KOBJECTS enumerations, the importance is set to 1, and the number is set to 0. 

```c
enum _KOBJECTS { 
… 
    DpcObject = 19, 
    ThreadedDpcObject = 26, 
…
}; 
```
```nasm
mov     [rcx+38h], rax
mov     [rcx+10h], rax
mov     [rcx+18h], rdx
mov     [rcx+20h], r8
```
Both DpcData and ProcessorHistory fields are set to 0, whilst the parameters DeferredRoutine and DeferredContext are assigned to their corresponding members.

# KeInitializeThreadedDpc 

```nasm
xor     eax, eax
mov     dword ptr [rcx], 11Ah
mov     [rcx+38h], rax
mov     [rcx+10h], rax
mov     [rcx+18h], rdx
mov     [rcx+20h], r8
retn
```
KeInitializeThreadedDPC is semantically equivalent to KeInitializeDpc apart from the fact that the base struct is given the value 0x11A, meaning that the type member is assigned 0x1A coming from the _KOBJECTS enumerations. We will see that this will make a difference when DPCs are inserted into the DPC queue. 

# KeInsertQueueDpc

```nasm
sub     rsp, 38h
xor     r9d, r9d
mov     [rsp+38h+var_18], 0 ; char
call    KiInsertQueueDpc
add     rsp, 38h
retn
```
On inspection, we can clearly see that KeInitializeDPC is just a wrapper for KiInsertQueueDPC. Arguments are passed, in order, in rcx, rdx, r8, r9 and on the stack, KiInsertQueueDPC is called, and the stack pointer is adjusted to deallocate the stack. 

# KeInsertQueueDpc

```nasm
movzx   r10d, word ptr [rcx+2]
```
At first, we see the contents of the memory address at offset 0x2 from the pointer to the DPC object moved into the lower 32 bits of the r10 register. This holds the number member of the DPC object. 
```nasm
mov     rbp, gs:20h
lea     r11, cs:140000000h
```
The next interesting snippet of code is this bit. As we can see, something at offset 0x20 from the GS segment is moved into rbp. On inspection of KeGetCurrentPrcb it is clear that rbp now holds a pointer to the KPRCB for a specific processor. Here is the struct for KPRCB: 
```c
struct _KPRCB
{
...
    ULONG Number;                                                           //0x24
...
    struct _KDPC_DATA DpcData[2];                                           //0x30c0
    UCHAR ThreadDpcEnable;                                                  //0x3128
...
}; 
```
```nasm
mov     [rsp+0A8h+var_30], rbx
cmp     r10w, ax
jnb     loc_214EC3
```
At this point r10, which we must remember holds the number member of the DPC object, is compared to ax, the lower 16 bits of rax. A conditional jump is then made. The next steps determine the KPRCB which will be used to insert the DPC. 
```nasm
mov     eax, [rbp+24h]
mov     [rsp+0A8h+var_78], eax
cmp     r10w, ax
jnz     loc_214F80
```
In the event that r10 is smaller than 0x500, a stack variable takes on the contents of the memory at 0x24 offset from the KPRCB pointer. This is the number member.  
```nasm
mov     rbx, rbp
```
Rbp, containing the pointer to the KPRCB, is then moved into rbx. 
```nasm
loc_214EC3:
mov     ecx, r10d
sub     ecx, eax
mov     [rsp+0A8h+var_78], ecx
mov     rbx, ds:rva KiProcessorBlock[r11+rcx*8]
```
The other eventuality is that the local stack variable is used to store the value obtained through the Dpc number field – 0x500. Then next step involves using KiProcessorBlock. But what is KiProcessorBlock? The KiProcessorBlock is simply an array of pointers to the KPRCB for each processor. Rbx instead takes on the KPRCB of the DPC’s target processor. The target processor can be changed using KeSetTargetProcessorDpc. 

The next interesting piece of code takes place here: 
![Image 1](https://raw.githubusercontent.com/KPRCB/KPRCB.github.io/main/assets/Image1.PNG)

It checks whether the DPC type is equivalent to 0x1A, a threaded DPC, and that the member ThreadDpcEnable is true on the target KPRCB. In the event that they are both true, 0x30C0 is loaded into eax, otherwise 0x30E8 is loaded into eax.  
```nasm
lea     rsi, [rbx+rax]  
```
The member at the given offset is then loaded into rsi. At offset 0x30CO in KPRCB there is an array of type _KDPC_DATA with two entries. This allows threaded DPCs to be inserted into a different list to normal ones. The _KDPC_DATA struct can be found here:  
```c
struct _KDPC_DATA 
{ 
    struct _KDPC_LIST DpcList;                                              //0x0 
    ULONGLONG DpcLock;                                                      //0x10 
    volatile LONG DpcQueueDepth;                                            //0x18 
    ULONG DpcCount;                                                         //0x1c 
    struct _KDPC* volatile ActiveDpc;                                       //0x20 
}; 
```
```nasm
mov     eax, [rsi+18h]
inc     dword ptr [rsi+1Ch]
inc     eax
mov     [rsi+18h], eax
mov     [rdi+28h], rdx
mov     [rdi+30h], r8
test    r12b, r12b
jnz     loc_41E412
```
Next, the value held at the memory address at offset 0x18 from the _KDPC_DATA pointer is moved into eax. This value is the DpcQueueDepth. The DpcCount is then incremented and so is eax. Then eax is moved into DpcQueueDepth. Additionally, Dpc SystemArguments are assigned to their corresponding members.
```nasm
loc_214D69:
cmp     byte ptr [rdi+1], 2
lea     rcx, [rdi+8]
mov     r15b, 1
jz      loc_214FFE
```
At this point, we can see rcx takes the value of the DpcListEntry and that if the DPC importance is equal to 2, a conditional jump is made. 

![Image 2](https://raw.githubusercontent.com/KPRCB/KPRCB.github.io/main/assets/Image2.PNG)

In the event that the importance is equal to 2, the list entry is inserted into the head of the list. Otherwise, the list entry is inserted into the tail of the list. 
```nasm
mov     qword ptr [rcx], 0
mov     rax, [rsi+8]
mov     [rax], rcx
mov     [rsi+8], rcx
```

In this way DPCs, can be inserted into the target (or arbitary) processors DPC list into the correct DPC list, threaded or normal, into a position based upon the importance.

# Conclusion

To conclude, this article has covered the basic principles of DPCs and the kernel functions and structures surrounding them. I hope this article has given you a better understanding of the mechanics of DPCs and their role in the operating system as a whole. 