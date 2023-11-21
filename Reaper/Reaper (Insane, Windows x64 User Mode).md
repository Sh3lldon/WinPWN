Reaper is an Insane level Windows x64 machine for User Mode and Kernel Mode Exploit Development.

![Title](/Reaper/Attachments/1.png)

In this note I am gonna write about exploitation of the dev_keycheck.exe executable file.
So, this a WinSock custom application, which checks user's key. 

Vulnerabilities:
1. Memory leak (through String Specifiers)
2. Buffer overflow (through user input key)

So, let's start.


### Analyzing the binary

First thing I always do is checking the binary. I mean the functionality of the binary without reversing.

The first thing I found after running the binary is it runs on 4141 port.

![[2.png]]
So we have a port, now let's connect and check.

![[3.png]]

Seems this binary will check user keys and activate them. let's try to find keys.

![[4.png]]

also from ftp server I downloaded the dev_keys.txt file. As you can see in this file exist some keys. Let's use some of them. (BTW if you look after the numbers, you can see that the another part looks like base64 encode. Keep in mind).

![[5.png]]

Yes, the binary successfully get the key and tried to activate it. Let's search vulnerabilities.


### Reversing

I will not tell about fully reversing of this binary, except I will tell about how I found the vulnerabilities and understand some unknown functions.

![[6.png]]

After accepting our connection, the such as printf fuction tells that "Client connected". After that the seem CreateThread function calls and gives some function as lpStartAddress parameter of this function. Let's go to this function.

![[7.png]]

Yes, we can see that this function like handleConnection fuction (BTW the good practice is renaming function, variables while reversing).

After choosing an option, our input located here:
![[8.png]]

s - socket descriptor
v7 - our input (also, I will rename it for better understanding)
2 - 2 bytes (size)
0 - flags

After that out input will be checked for possible options (1, 2, 3). 
![[9.png]]

![[10.png]]

We know that the 3rd option is just exit. After that we have only 2 options the 1st and 2nd. As we know, the first option just recieve the key and just store it (my thoughts) and the second option will activate it. Let's go deeper.


#### 1st option

![[9.png]]

The key will located at v10 variable, let's rename it. The max length of a key is 0x1000 bytes.
After receiving the key, it will check the checksum in this function "sub_140001760". Let's rename it and try to reverse.

![[11.png]]

The length of the key must be equals or more than 23 bytes. Also, every character must be between 0x32 (space) and 127. The 4th, 10th, 14th and 18th characters must be dash ('-').
If these rules work, key will be true and use the key from dev_keys.txt file, they work fine also. So, this function is checking the format of the key.


#### 2nd option

![[12.png]]

In this options I think the keys will be activated. Also, after this options the binary send the key back for us, here might be a leak vuln (keep in mind).

![[13.png]]

The second if condition looks interesting, because as one of the parameters it takes our input.

![[14.png]]

![[15.png]]

Let's go to this function.

![[16.png]]


The possible thought is this function opens the keys.txt file and tried to find the key, that we entered. But, before doing that we have also one function with socket descriptor (s) and our key (inputKey). Let's reverse it.

![[17.png]]

Hmmmm. one more checking function? Mb
Let's try to understand what this function does. 

We see the memset and memmove functions. Here mb the buffer overflow vulnerability.
the Str variable will point to address of inputKey + 24. That means the Str will be start after the key format. For example we paste the "100-FE9A1-500-A270-0102-U3RhbmRhcmQgTGljZW5zZQ" key. The length of the format "100-FE9A1-500-A270-0102" equals to 23 and plus one dash equals to 24. 

![[18.png]]

For me more interesting these functions. The Size variable equals to 0, but for argument it gives a pointer to this variable, so the Size variable mb changed. Also, we have Str (key + 24) and the length of the Str.

![[19.png]]

It is hard to understand what is going here, so let's switch to the WinDBG.

The Best practice while dynamic reversing with changing the start address to base address of the binary in WinDBG. Let's me show you.

with lm command  in WinDBG we can see the list of modules, which loaded in the binary and process.

![[20.png]]

The base address of the binary is equals to address of ReaperKeyCheck module. Let's copy that and rebase the program in IDA.

![[21.png]]

Also, in the Options -> Generation mark the lines prefix
![[22.png]]
With that you see the address of the every instruction in disassembly tab.


Let's paste a breakpoint to the sub_7FF699E312D0 function.

![[23.png]]

Repeate the steps like in the beggining.

![[24.png]]

As you can see, we hit the breakpoint, Let's analyze the parameters and the results.
About calling convention on Windows x64. The 1st parameter located in ECX, 2nd in EDX, 3rd in E8, 4th in E9, and other will push into the stack with reverse order, for example the last argument will be pushed first because the stack growth to low addresss.

1st parameter (Str or inputKey + 24):
![[25.png]]

2nd parameter (inputLen):
![[26.png]]

3rd parameter (pointer to Size var):
![[27.png]]

So, seem every parameter is OK.
Let's the result of the function. The result of the function will be stored in RAX register, for example it may give 0, 1 or another values, address of the memory etc.
I will execute the p command which is step over.

![[28.png]]

![[29.png]]

Interesting....
The RCX and RAX registers point to one memorey address and contain Standard License message. 
The pointer to Size var, contains 0x11 (17 in decimal), so this the length of the decoded key value.

![[20.png]]

So the first function is base64 decoder function, now we have understanding. It will help us. For the experiment I will give you some interesting question, what if we will give not base64 encoded key?

Let's switch to memmove function and see can we overflow the buffer.

![[31.png]]

RCX - new allocated memory (destination)
RDX - decoded key value (source)
R8 - size of decode key value

What if we will give a large argument and try to overwrite RIP,  but before let's find mem leak vuln.
If you remeber, after activating the key, binary will show the name of the key, what if we will give %p or %x string specifiers.

### Leak of an address (String specifiers)

In this binary DEP and ASLR are on, so for bypassing ASLR we need to get a leak.

![[32.png]]

Awesome!! Let's try to understand why we got a leak.

![[33.png]]
Here calling the vsprintf fuction and let's see the arguments

![[34.png]]

We have new allocated buffer, and the message "Checking key: " and the key value "%p".
So, the %p means the pointer specifier in C/C++. With this is specifer we can get the address from the memory. Let's see the resulsts after the function. Paste the breakpoint into send function at the end.

![[36.png]]

As you can see the buf variable contains the leak address.

### Buffer overflow

Let's crate a cyclic pattern for 1000 bytes and use it.

![[37.png]]

![[18.png]]

So, we have key format, after the key formation we can paste anything. I pasted a cyclic pattern and encode it in base64 format and in the end just add the key and the encode pattern. Let's see the resulsts.

![[39.png]]

I got access violation and the offset is in waaa message, let's understand in which offset located waaaa.

![[40.png]]

So, the offset equals to 88, that is great, we have a lot of place for ROP chain and shellcode.
