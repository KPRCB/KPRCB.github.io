---
layout: post
title: Unveiling the mechanics of APCs
date: 2023-08-31 21:01
categories: [Reverse engineering, Windows, Kernel]
---

# Introduction

Asynchronous procedure calls (APCs) are functions that allow code to be executed within the context of a particular thread. There are four types of APCs according to MCDN, ‘Special user-mode APCs', 'Regular user-mode APCs', 'Normal kernel APCs', and 'Special kernel APCs’. Special kernel APCs execute at APC level and normal kernel APCs and user APCs execute at passive level. Each thread has its own APC queue. APCs can hence be used to suspend threads, shutdown processes, and code injection. 

# KeInitializeApc 

An APC can be described by an APC object. The structure of which is shown below: 

```c
struct _KAPC
{
    UCHAR Type;                                                             //0x0
    UCHAR SpareByte0;                                                       //0x1
    UCHAR Size;                                                             //0x2
    UCHAR SpareByte1;                                                       //0x3
    ULONG SpareLong0;                                                       //0x4
    struct _KTHREAD* Thread;                                                //0x8
    struct _LIST_ENTRY ApcListEntry;                                        //0x10
    VOID* Reserved[3];                                                      //0x20
    VOID* NormalContext;                                                    //0x38
    VOID* SystemArgument1;                                                  //0x40
    VOID* SystemArgument2;                                                  //0x48
    CHAR ApcStateIndex;                                                     //0x50
    CHAR ApcMode;                                                           //0x51
    UCHAR Inserted;                                                         //0x52
}; 
```

The arguments: Apc, Thread, TargetEnvironment, KernelRoutine, RundownRoutine, NormalRoutine, Mode, and Context, are passed into the function in rcx, rdx, r8, r9 and on the stack respectively.
```nasm
mov     byte ptr [rcx], 12h
mov     r10, rcx
mov     byte ptr [rcx+2], 58h
cmp     r8d, 2
jz      short loc_2F9424
```
First 0x12 (18) is moved into the base of the struct. The type member is used to identify the kernel objects and is taken from the _KOBJECTS enumerations, as shown. 
```c
enum _KOBJECTS 
{ 
... 
    ApcObject = 18, 
... 
}; 
```
In addition to this the size of the struct (0x58) is moved into the size member. Proceeding this, a comparison between the r8 register, TargetEnvironment, and 2 is made. This is a check to see if the APC TargetEnvironment is in the current environment.
```nasm
loc_2F9424:
mov     r8b, [rdx+24Ah]
jmp     short loc_2F93E0
```
In the event, that r8 == 2, then TargetEnvironment takes on the value of the Threads ApcStateIndex. 
```nasm
loc_2F93E0:
mov     rax, [rsp+arg_20]
mov     [rcx+50h], r8b
mov     [rcx+28h], rax
mov     [rcx+8], rdx
mov     rdx, [rsp+arg_28]
mov     [rcx+30h], rdx
mov     rax, rdx
neg     rax
mov     [rcx+20h], r9
sbb     rcx, rcx
and     rcx, [rsp+arg_38]
neg     rdx
sbb     al, al
and     al, [rsp+arg_30]
mov     [r10+51h], al
mov     [r10+38h], rcx
mov     byte ptr [r10+52h], 0
retn
```
The ApcStateIndex takes on the value of the TargetEnvironment, then the members: RundownRoutine, Thread, NormalRoutine, KernelRoutine take on the value of the corresponding parameters. There is then a check whether the APC is special or not. If the APC has a NormalRoutine then ApcMode takes on the value of Mode parameter. Otherwise, it takes the value of 0. This enum describes the different modes. 
```nasm
enum _MODE { 
    KernelMode = 0, 
    UserMode = 1, 
    MaximumMode = 2 
}; 
```
Additionally, if there is a normal routine, NormalContext takes the value of the context. Lastly, the inserted member is set to 0. 

# KeInsertQueueApc 

The first interesting use of the APC object and thread object comes here: 
```nasm
test    dword ptr [rdi+74h], 4000h
jz      loc_2FB713
```
Test, for those who don’t know, is similar to cmp but instead of a subtraction, an AND operation takes place. But to understand this operation we must look at the _KTHREAD structure first. 
```c
struct _KTHREAD 
{ 
... 
    union 
    { 
        struct 
        { 
            ULONG AutoBoostActive:1;                                        //0x74 
            ULONG ReadyTransition:1;                                        //0x74 
            ULONG WaitNext:1;                                               //0x74 
            ULONG SystemAffinityActive:1;                                   //0x74 
            ULONG Alertable:1;                                              //0x74 
            ULONG UserStackWalkActive:1;                                    //0x74 
            ULONG ApcInterruptRequest:1;                                    //0x74 
            ULONG QuantumEndMigrate:1;                                      //0x74 
            ULONG UmsDirectedSwitchEnable:1;                                //0x74 
            ULONG TimerActive:1;                                            //0x74 
            ULONG SystemThread:1;                                           //0x74 
            ULONG ProcessDetachActive:1;                                    //0x74 
            ULONG CalloutActive:1;                                          //0x74 
            ULONG ScbReadyQueue:1;                                          //0x74 
            ULONG ApcQueueable:1;                                           //0x74 
            ULONG ReservedStackInUse:1;                                     //0x74 
            ULONG UmsPerformingSyscall:1;                                   //0x74 
            ULONG TimerSuspended:1;                                         //0x74 
            ULONG SuspendedWaitMode:1;                                      //0x74 
            ULONG SuspendSchedulerApcWait:1;                                //0x74 
            ULONG CetUserShadowStack:1;                                     //0x74 
            ULONG BypassProcessFreeze:1;                                    //0x74 
            ULONG Reserved:10;                                              //0x74 
        }; 
        LONG MiscFlags;                                                     //0x74 
    }; 
... 
    union 
    { 
        struct _KAPC_STATE ApcState;                                        //0x98 
        struct 
        { 
            UCHAR ApcStateFill[43];                                         //0x98 
            CHAR Priority;                                                  //0xc3 
            ULONG UserIdealProcessor;                                       //0xc4 
        }; 
    }; 
...  
    union 
    { 
        struct _KAPC_STATE SavedApcState;                                   //0x258 
        struct 

        { 
            UCHAR SavedApcStateFill[43];                                    //0x258 
            UCHAR WaitReason;                                               //0x283 
            CHAR SuspendCount;                                              //0x284 
            CHAR Saturation;                                                //0x285 
            USHORT SListFaultCount;                                         //0x286 
        }; 
    }; 
}; 
```

A logical AND operation is applied to this bitfield using 0x4000. When looking at 0x4000 in binary form. We see that every bit is a 0 apart from the 15th. Therefore the use of 0x4000 and Test is to see whether the 15th member of the bitfield is a 1. This member happens to be ApcQueueable. If ApcQueueable is true then the ZF is set to 0, and the jump is not made. Otherwise, we arrive here: 
```nasm
cmp     byte ptr [rsi+52h], 0
jnz     loc_2FB713
```
Here the contents of the memory address at 0x52 offset to rsi, which contains the APC, is compared to 0. At offset 0x52, is the Inserted member. If the contents happened to be equivalent to 0 the jump is not made. In this way, the code that proceeds this will only execute given that APCs are queueable on the target thread and the APC hasn’t already been inserted. 
```nasm
mov     rcx, rsi        ; Apc
mov     byte ptr [rsi+52h], 1
mov     [rsi+40h], r13
mov     [rsi+48h], r12
call    KiInsertQueueApc
mov     r8b, bpl
mov     rdx, rsi
mov     rcx, r14
call    KiSignalThreadForApc
```
Next, the APC is moved into rcx, ready to be passed into KiInsertQueueApc, APC’s Inserted member is set to 1, and the system arguments are assigned to their corresponding APC members. KiInsertQueueApc and KiSingalThreadForAPC are then called. 

# KiInsertQueueApc 

To simplify the process and for brevity, we will look at the execution flow given that the APC is of mode kernel. 

![Image 3](https://raw.githubusercontent.com/KPRCB/KPRCB.github.io/main/assets/Image3.png)

The ApcStateIndex of the APC is compared to the ApcStateIndex of the thread to determine whether the thread’s environment is wanted to be used. This then determines which _KAPC_STATE is used from the _KTHREAD structure. Important to the next piece of code, the r9 register is zeroed. Here is the _KAPC_STATE structure: 
```c
struct _KAPC_STATE
{
    struct _LIST_ENTRY ApcListHead[2];                                      //0x0
    struct _KPROCESS* Process;                                              //0x20
    union
    {
        UCHAR InProgressFlags;                                              //0x28
        struct
        {
            UCHAR KernelApcInProgress:1;                                    //0x28
            UCHAR SpecialApcInProgress:1;                                   //0x28
        };
    };
    UCHAR KernelApcPending;                                                 //0x29
    union
    {
        UCHAR UserApcPendingAll;                                            //0x2a
        struct
        {
            UCHAR SpecialUserApcPending:1;                                  //0x2a
            UCHAR UserApcPending:1;                                         //0x2a
        };
    };
};
```
```nasm
loc_2FB244:
lea     r8, [rax+rdx]
movsx   rax, byte ptr [rcx+51h]
cmp     [rcx+30h], r9
jz      loc_2FB2E3
```
Rax now contains the ApcMode and a comparison between the NormalRoutine and r9 takes place. The jump is made if the ApcMode is 0. Otherwise, the execution flow continues here: 
```nasm
test    al, al
jnz     short loc_2FB286
```
Al, the lowest 8 bits of the rax register, is used in a Test operation. Since jnz is used, the jump is only made if the ZF is 0, so the jump is only made if the ApcMode not 0. From the _MODE enumerations, this means that the Apc is kernel. 

![Image 4](https://raw.githubusercontent.com/KPRCB/KPRCB.github.io/main/assets/Image4.png)

Then using _KAPC_STATE the APC is inserted into the tail of the kernel mode list. 

# Conclusion 

This article briefly touches on the mechanics of APCs in the kernel and a variety of kernel functions and structures. This does not, however, go into detail about special APCs or usermode APCs. Thanks for reading, I hope this provides some level of insight.