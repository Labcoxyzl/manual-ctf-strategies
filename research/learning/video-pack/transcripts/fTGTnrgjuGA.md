# Ghidra quickstart & tutorial: Solving a simple crackme

Source: https://www.youtube.com/watch?v=fTGTnrgjuGA

English caption extraction; automatic captions may misrecognize commands. Rolling duplicate lines removed.

[00:02] welcome to this short introduction into
[00:02] the JIRA software reverse engineering
[00:04] suite in this video we will look at
[00:07] cracking a simple crackme called easy
[00:09] reverse from the website crack missed
[00:11] one download the file and extract it
[00:14] using the password crack miss dot one
[00:25] when you run the binary for example on a
[00:25] virtual machine you can see that it
[00:26] expects a password and that password is
[00:29] exactly what we are going to try to
[00:31] reverse-engineer using jira so let's go
[00:36] ahead and start right well the first
[00:38] time you start I draw you'll be greeted
[00:40] by the short License Agreement just to
[00:42] degree because nobody reads those anyway
[00:52] once dry dryer has
[00:52] the project manager window we will throw
[00:55] away the other windows because we don't
[00:57] care about those and focus on the
[00:58] project manager we create a new project
[01:01] by hitting file new project and select a
[01:03] non shared project then we select a
[01:06] project directory and give our project a
[01:10] nice name
[01:19] you can see our project is now in the
[01:19] project manager to import a binary we
[01:22] can either use file import file or we
[01:24] can simply drag and drop the file into
[01:26] the project manager this will bring up
[01:30] the import dialog where we need to
[01:32] ensure that the format was detected
[01:34] correctly and that the other binary
[01:36] information such as the architecture and
[01:39] the bit size was detected correctly for
[01:41] example you might want to change the
[01:43] compiler here or under certain
[01:45] circumstances even select an entirely
[01:47] different architecture
[01:53] in this case we are happy with what
[01:53] Hydra detected and we'll just hit okay
[01:56] and let dry dry import the binary
[02:02] once the import is done it will bring up
[02:02] this short import results summary where
[02:04] you can see the number of functions
[02:06] symbols and other data you can also see
[02:09] that the Lipsy was not found and that
[02:11] there are six unresolved external
[02:13] symbols we don't care about these in
[02:15] this case and so we just hit OK
[02:22] afterwards
[02:22] click on our binary to start the code
[02:24] browser the first thing the code browser
[02:27] will ask us is whether we want to
[02:29] analyze the binary we had yes and this
[02:31] will bring up the analysis options in
[02:33] here you can see that Hydra comes with a
[02:36] ton of analyzers for example an ASCII
[02:38] string analyzer that tries to detect
[02:41] ASCII strings in your binary we could
[02:43] change some options for example the
[02:44] minimum string length but we'll just
[02:46] leave it on default in this case we'll
[02:49] also leave all the other analyzers on
[02:51] default the only thing we are going to
[02:53] enable is the decompiler parameter ID
[02:55] just because it often improves our D
[02:58] compilation results hit the analyze
[03:01] button and you will be able to see the
[03:03] progress in the bottom right and you
[03:05] will also see some of your eye elements
[03:07] slowly updating on a small binary like
[03:10] this analysis is pretty fast but on a
[03:12] bigger one you might wait a couple of
[03:14] minutes so let's maximize the window and
[03:16] start exploring the main window in the
[03:19] code browser is called the listing
[03:21] window
[03:22] it contains your disassembly listing
[03:24] your data and can even display images
[03:27] and so on if you click for example a
[03:29] function in the listing window you might
[03:30] notice that other elements update in
[03:33] accordance to what you selected if you
[03:36] are having trouble with scrolling in the
[03:38] listing window there's already a patch
[03:40] available on github with a simple drag
[03:42] and drop jar file you can put into your
[03:45] chaya installation if you're missing the
[03:48] colorful navigation bar from either you
[03:51] can enable a similar function by going
[03:53] to the arrow in the top right and
[03:55] selecting show overview this will show a
[03:59] colorful overview indicating strings and
[04:01] data to the right of your listing view
[04:03] if you hover over a jump or a data
[04:06] target a small pop-up will show up you
[04:09] can disable this one by clicking the
[04:10] small pop-up button in the menu bar but
[04:13] I personally keep it enabled most of the
[04:15] time the next important window is the
[04:18] decompile window where you will find the
[04:20] D compilation result for the function
[04:22] you have currently selected in your
[04:23] listing the next window is the program
[04:27] trees window which contains the
[04:28] different sections from the binary for
[04:30] example the BSS and the data segment
[04:33] underneath it is the symbol tree window
[04:35] which contains the imports exports
[04:37] functions labels classes and namespaces
[04:40] found in the program
[04:42] underneath the symbol tree is the data
[04:44] type manager where we can manage data
[04:47] types and so on but we will ignore that
[04:49] in this video then underneath the
[04:52] listing we have the console window which
[04:54] we will also not use in this video
[04:56] normally it contains the output of
[04:57] scripts and other stuff
[05:05] another important window in Hydra is the
[05:05] bytes window which is basically the
[05:06] hexton window so it allows you to
[05:08] explore your binary in hex format we'll
[05:11] make it a bit bigger by dragging the
[05:13] title bar of it into our listing view
[05:16] this will merge the two windows into a
[05:19] single one and you will be able to
[05:21] switch between them using the tabs on
[05:23] the bottom of the screen I also like to
[05:26] enable the S key view of the hex stamp
[05:29] by clicking the small wrench and
[05:30] enabling the S key view
[05:37] if you want to create a new split you
[05:37] can simply drag the title bar of a
[05:39] window until a small arrow appears drop
[05:42] the window there and it will create a
[05:44] new split if you want to have a window
[05:46] as a separate window simply drag it out
[05:48] until a small window icon appears if you
[05:53] ever accidentally close a window you can
[05:55] bring it back by simply selecting it
[05:57] from the window menu
[06:03] so let's get started with reverse
[06:03] engineering this crackme
[06:05] research the symbol tree for the main
[06:07] function which is basically the entry
[06:09] point into our program we double-click
[06:12] it and this will bring both the listing
[06:14] entity compiler into our main function
[06:17] as you can see the decompiler try to
[06:20] infer the signature of the main function
[06:22] the good thing is that the C standard
[06:25] defines exactly how the main function
[06:27] signature looks like and so we can just
[06:29] copy it from the C standard we go back
[06:33] into Jireh right click this function
[06:35] signature and hit edit function
[06:37] signature we can simply paste in the
[06:40] signature from the C standard and you
[06:42] can see that the types and the names
[06:44] were taken over from our pasted
[06:47] signature one problem though is that the
[06:50] square brackets of the arc V argument
[06:53] were not treated as an array but instead
[06:55] as part of our function name so we need
[06:57] to edit the function signature again and
[06:59] change it to be a pointer to a pointer
[07:03] so we hit OK and we can see that this
[07:06] cleaned up our D compilation result
[07:08] massively if we hit undo which you've
[07:12] been missing for years have you been
[07:13] using either we can see how with the D
[07:16] compilation result was much worse before
[07:18] we adjusted the types compared to either
[07:22] where you spend a lot of time in the
[07:24] graph you enjoy are the main focus is
[07:26] the decompile view and the listing view
[07:28] so you want to make sure that you use
[07:31] the correct types wherever possible just
[07:33] to help the decompiler get you a great
[07:36] result so let's start going through our
[07:39] main function line by line we ignore the
[07:41] declaration of SOR 1 and look at our if
[07:44] Clause which checks the number of
[07:45] arguments supplied to the program as you
[07:48] can see if you select something in the D
[07:50] compiler it also gets selected in the
[07:53] listing in this case the number of
[07:56] arguments needs to be 2
[07:58] this means that we need to supply one
[08:00] argument to our program as the first
[08:03] argument that is always given into AC
[08:05] program is the program name to document
[08:08] this we want to add a comment to this
[08:10] line so we either right-click and select
[08:12] comments or
[08:14] we simply hit the semi-colon key this
[08:16] will bring up a window where you can
[08:18] enter different types of comments for
[08:20] example an end-of-line comment which
[08:23] we'll just put in as your l comment
[08:25] right now a pre comment a post comment a
[08:31] repeatable comment which we will ignore
[08:33] for now and the plate comment we hit ok
[08:36] and we can see that only the pre comment
[08:38] appears in our decompile view but if we
[08:41] go into you the listing view we can see
[08:44] that our post comment appears underneath
[08:45] the instruction the UL comment appeared
[08:49] behind the instruction the big plate
[08:51] comment appeared above the instruction
[08:54] in a nice block and the pre comment
[08:56] appeared right on top of the instruction
[08:58] so let's remove all the comments we just
[09:01] created and replace the pre comment with
[09:03] something more useful so for example in
[09:07] this case we wanted to say check if we
[09:09] have one argument remember that our c
[09:12] equals two means we have one argument
[09:15] and not two arguments the next line is a
[09:19] string length and so because we see that
[09:22] the string length is running on the
[09:24] first argument supplied to the program
[09:26] we can give as ba one a more useful name
[09:29] for example arc 1 or argument 1 length
[09:33] for that we can simply you right click
[09:36] on s bar 1 and select rename' variable
[09:38] or we simply hit the L key the next line
[09:43] is again an if clause that checks if
[09:45] argument 1 length is equal to 10 and so
[09:48] we will document this by again hitting
[09:50] the semicolon key and adding a comment
[09:53] so we remember what exactly is going on
[09:55] here
[09:57] and then we can already go up to the
[10:01] next line which checks whether the fifth
[10:05] character because we start indexing by
[10:09] 0f argument one is an add character and
[10:13] so again we will enter a comment to
[10:16] document what we found and hit ok
[10:24] let's increase the size of the D
[10:24] compilation window a bit and you can see
[10:26] that once we go through these three if
[10:29] clauses we get our flag printed out
[10:32] otherwise it will display the usage of
[10:35] the program so we can double click on
[10:37] this and we can see the D compilation
[10:39] results for the usage function which
[10:42] simply prints the program name and
[10:44] afterwards exits by clicking the back
[10:47] button we go back to where we just left
[10:49] and we are pretty confident and having
[10:52] figured out what exactly we need to do
[10:54] to solve this crack knee we need one
[10:57] argument we need a string length of the
[10:59] argument of 10 and we need to have an
[11:02] add character at the fifth place so
[11:04] let's go ahead and test this in the
[11:06] terminal we go again into our linux
[11:09] shell execute the program and then have
[11:12] one two three four and at sign six seven
[11:15] eight nine ten we hit return and yes
[11:18] we've cracked our first crack me using
[11:20] Deidra and that without reading a single
[11:22] line of assembly I hope you enjoyed this
[11:25] short introduction and that you will
[11:27] tune in for more in the future
