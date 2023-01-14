
# PwnableWalkthrough
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


![image](https://user-images.githubusercontent.com/56035342/212479565-354078e2-4cf4-4163-a0d8-63c2d5de9d8f.png)
