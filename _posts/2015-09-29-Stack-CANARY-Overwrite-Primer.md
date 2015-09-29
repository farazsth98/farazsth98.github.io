---
layout: post
title: Overwriting Stack CANARY - Primer
category: Exploitation
tags: Exploitation asciinema RE
---

> [canaries]({{site.url}}/assets/canaries)

Hello,

This video/tutorial is showing an example of how information leaks can lead to bypassing stack canaries.
The process is mostly explained via CLI comments, feel free to pause the video and look around the debugger, register values etc...
The video is playing x3 the speed

{% highlight bash %}
➜  canaries/  checksec canaries
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH  FORTIFY FORTIFIED FORTIFY-able  FILE
Partial RELRO   Canary found      NX enabled    No PIE          No RPATH   No RUNPATH   Yes 2       41  canaries

{% endhighlight %}

<script type="text/javascript" src="https://asciinema.org/a/b4e9ze1ftdfubwpkvuldkhdqo.js" id="asciicast-b4e9ze1ftdfubwpkvuldkhdqo" async data-speed="3"></script>

Source code of the binary:

{% highlight C %}
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "utils.h"

#define STDIN 0

//gcc --static -fstack-protector-all -mpreferred-stack-boundary=2 -o canaries canaries_primer.c

void selectAMessage() {
    char buf[512];
    scanf("%s", buf);
    printf(buf);
    if(strcmp(buf, "A") == 0){
        printA();
    }else if(strcmp(buf,"B") == 0){
        printB();
    }else if(*buf == "C"){
        printC();
    }else if(buf == 1337){
        printf("\nExcuse me. I wanna learn how to hack!\n");
        exit(EXIT_FAILURE);
    }else{
        printf("\nSorry. Try again.\n");
        selectAMessage();
    }
    return;
}

void printA(){

    printf("\n\n");
    printf("|#-----------------------------------------------------#|\n");
    printf("|#     BYPASSING STACK CANARIES - Phrack Issue 0x38    #|\n");
    printf("|#-----------------------------------------------------#|\n\n");
    printf("'When a buffer overwrites a pointer...  The story of a restless mind.'\n"\
            "This article is an attempt to demonstrate that it is possible to exploit\n"\
            "stack overflow vulnerabilities on systems secured by StackGuard or StackShield\n"\ 
            "even in hostile environments (such as when the stack is non-executable). \n\n");
}

void printB(){
    printf("\n\n");
    printf("|#-----------------------------------------------------#|\n");
    printf("|#                  There is no spoon                  #|\n");
    printf("|#-----------------------------------------------------#|\n\n");
    printf("I talked with Crispin Cowan <crispin@cse.ogi.edu>, one of the StackGuard\n"\
            "developers and he proposed a remediation against above hack.  Here's his idea:\n"\
            "The XOR Random Canary defense:  here, we adopt Aaron Grier's ancient\n"\
            "proposal to xor the random canary with the return address.  The canary\n"\
            "validation code used on exit from functions then XOR's the return address\n"\
            "with the proper random canary (assigned to this function at exec() time)\n"\
            "to compute what the recorded random canary on the stack should be.  If the\n"\
            "attacker has hacked the return address, then the xor'd random canary will\n"\
            "not match.  The attacker cannot compute the canary to put on the stack\n"\
            "without knowing the random canary value.  This is effectively encryption\n"\
            "of the return address with the random canary for this function.\n"\
            "\n"\
            "The challenge here is to keep the attacker from learning the random\n"\
            "canary value.  Previously, we had proposed to do that by just surrounding\n"\
            "the canary table with red pages, so that buffer overflows could not be\n"\
            "used to extract canary values.  However, Emsi's [described above] attack\n"\
            "lets him synthesize pointers to arbitrary addresses.\n");
}

void printC(){
    printf("\n\n");
    printf("|#-----------------------------------------------------#|\n");
    printf("|#                    Authors' note                    #|\n");
    printf("|#-----------------------------------------------------#|\n\n");
    printf("This article is intellectual property of Lam3rZ Group.\n"\
            "Knowledge presented here is the intellectual property of all of mankind,\n"\
            "especially those who can understand it. :)\n");
}


int main(int argc, char* argv[])
{
    disable_buffering(stdout);
    printf("\n\n\n");
    printf("|#-----------------------------------------------------#|\n"\
           "|#           Welcome to Stack Canaries Primer          #|\n"\
           "|#-----------------------------------------------------#|\n"\
           "\n"
           "\t==> We are going to learn about stack canaries. <==\n"\
           "\t[+] I have three very important messages for you. Please choose A, B or C: ");
    selectAMessage();

    printf("\n...I hope you learned something...\n");

    printf("\nMany thanks to quend for letting me reuse her code from one of the RPISEC MBE labs.\n");

    printf("\n\t[===] The End !\n\n");
    return EXIT_SUCCESS;
}
{% endhighlight %}

* Special thanks to 'quend' for letting me re-use her code from one of the RPISEC MBE labs !