# Reversing and Cracking first simple Program - bin 0x05

Creator English track retained but not used for timing: last cue starts at 619s, beyond 543s video runtime. Automatic original-English track is duration-bounded.

[00:10] [Music]
[00:10] I have written a small C program it's
[00:12] supposed to be a simple license check so
[00:15] you can execute it and you can supply a
[00:18] key as an argument and it will be
[00:20] checked our goal is to crack this
[00:23] program so we don't have to use a valid
[00:24] license key I've made this program
[00:27] available through a GitHub repository
[00:29] you can download from gab.com overflow
[00:32] and the repository name life overflow
[00:34] YouTube or you can install git with sud
[00:37] sudo appg install git and get the whole
[00:40] repository with Git clone and the
[00:42] address you can see on GitHub we will
[00:45] probably talk more about what get is
[00:47] later for now it's enough to know that
[00:49] it's a way how developers can program
[00:52] together on a project and I use it to
[00:54] share some
[00:56] stuff to have a look at the binary
[00:58] assembly code we can use a program
[01:00] called GDB the new debugger so type GDB
[01:05] and the path to the binary so every C
[01:07] program has a main function remember so
[01:10] let's type in disassemble main which
[01:13] will display all assembler instructions
[01:15] from the main function but do you see
[01:18] how ugly that looks that's horrible
[01:20] horrible AT&T syntax so type in set
[01:24] disassembly flavor Intel remember that
[01:27] you can use tab completion here as well
[01:30] now disassemble main again and now it's
[01:32] much more readable okay so it looks
[01:36] complicated but you can ignore most of
[01:38] it first of all get a higher level view
[01:41] of it it doesn't make sense to start
[01:42] going through this instruction by
[01:44] instruction this main function obviously
[01:47] calls other functions so just draw a
[01:49] mental picture of the rough control
[01:52] flow I will actually print out this
[01:54] assembler code and use a pen that's how
[01:57] I did it in the beginning and still do
[01:59] it when I counter more complex code and
[02:02] remember to just ignore most of the
[02:04] stuff concentrate on the actual
[02:07] flow so at this start it arrives at a
[02:10] compare with number two and afterwards a
[02:13] jump not equal so something is checked
[02:16] if it is
[02:25] two if that is the case we proceed to a
[02:25] print F which we know is a function to
[02:28] display text
[02:31] then comes a string
[02:38] compare if you don't know that function
[02:38] read the man page of it Man 3 string
[02:41] compare so this Compares two strings and
[02:44] returns zero if both strings were the
[02:51] same after that call we see another jump
[02:51] not
[03:00] equal so if the zero flag is not said
[03:00] there will be a puts call use the main
[03:03] page to figure out what it does but it
[03:06] just prints text like
[03:15] printer so if the original compare with
[03:15] the number two was not true then it
[03:17] would jump to the address
[03:25] 4623 so in that case it prints some
[03:25] other text with puts and exits
[03:32] I always add the address or at least
[03:32] part of the address from important
[03:34] locations so I know where I am this will
[03:37] help you later when we step through the
[03:39] program now we have one branch
[03:53] text some jumps are still missing but
[03:53] you can add them to get a nice control
[03:55] flow
[03:56] graph now let's actually execute this
[03:59] and step through it you can then draw
[04:02] which path through the graph you have
[04:04] taken on your paper to do this we first
[04:06] set a break point at the start of main
[04:09] with break main breakpoint is set now
[04:12] use run to start the program starting
[04:16] the program and we hit the breakpoint
[04:18] one at this address a breakpoint is a
[04:21] point where execution
[04:23] stops now look at the registers with
[04:26] info registers here you can see the RP
[04:29] uh the the instruction pointer points to
[04:31] the first address in main now use SI to
[04:36] Step One instruction now we are at the
[04:38] new address in main info registers and
[04:40] you see the changed instruction
[04:47] pointer so now just step through it and
[04:47] follow the addresses in your control
[04:48] graph but use ni i instead of Si because
[04:52] Si would step into function calls but we
[04:54] only want to step through this main
[04:56] function and not follow stuff like puts
[05:10] okay did you notice when we jumped the
[05:10] jump was at 5D 0 and then the next
[05:13] instruction was at
[05:15] 623 so we followed the jump which means
[05:18] whatever was compared to two was not
[05:26] two and then the program printed the
[05:26] usage information after 628 which was
[05:29] the last puts call so we can write down
[05:32] that this puts prints the usage
[05:38] information now it's pretty clear that
[05:39] we didn't pass a key to this program
[05:41] which means the check was looking at the
[05:43] arguments if we supplied a license key
[05:46] so let's run the program again but this
[05:48] time with a random license
[05:57] key yes we want to start the program
[05:57] again now do the same n i and I and
[06:01] I now we are at 5D 0 again will we jump
[06:05] this
[06:06] time no cool so the next Branch we
[06:09] expect is at
[06:11] 609 let's an i and see what
[06:15] happens ah another print text so that
[06:19] print f is the info that a license key
[06:22] will be
[06:29] checked n i now comes the branch okay we
[06:29] are arrived at
[06:30] 609 let's see where we are afterwards at
[06:34] 617 so we did jump which means that the
[06:38] string compare failed and when we
[06:40] continue with an i we see that it's
[06:45] wrong okay let's set a breakpoint just
[06:47] before the last compare and run the
[06:49] program again remember that you can
[06:52] easily copy and paste values in the
[06:55] terminal by simply marking something and
[06:57] pressing your mouse wheel
[07:00] now run again break point one now
[07:04] continue this will run the program
[07:06] normally again until we hit the next
[07:09] breakpoint now it stopped before we
[07:11] execute the test eax
[07:13] eax eax just refers to the first 32-bit
[07:17] of the 64-bit Rax register so its value
[07:21] is hex e let's set this to zero which
[07:25] would indicate that the string compare
[07:27] was correct and returned zero
[07:30] set dollar E equals to zero info
[07:34] registers and you see that it's now zero
[07:37] now use an i again to step and follow
[07:39] your control
[07:50] path access granted yay so we
[07:50] circumvented the license
[08:00] check and you can always write your own
[08:00] little C program trying to make it more
[08:03] secure and then crack it yourself again
[08:05] you will notice that it's impossible to
[08:08] make a program
[08:10] uncrackable those kind of challenges are
[08:12] called crack me people create small
[08:15] programs that have to be cracked or more
[08:17] often you have to create a valid key
[08:19] again if you think something like this
[08:21] is fun check out Crack
[08:28] m.de creating control graphs like we
[08:28] just did is pretty useful that's why
[08:31] there are some programs that do that for
[08:33] us here are three different example of
[08:35] this specific control
[08:38] graph first is from the hopper
[08:42] disassembler second is from
[08:44] Ida and the last one is from radar it
[08:48] see you hopefully next time when we use
[08:50] some different tools to explore this
[08:52] license check binary a bit more
