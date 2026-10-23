# Introduction to Memory Forensics with Volatility 3

Source: https://www.youtube.com/watch?v=Uk3DEgY5Ue8

English caption extraction; automatic captions may misrecognize commands. Rolling duplicate lines removed.

[00:01] welcome back everyone today is an
[00:01] introduction to volatility 3 and
[00:03] volatility is a ram analysis tool that
[00:06] we use from the command line it has a
[00:08] lot of different options for parsing
[00:09] information out of a memory image on a
[00:12] computer there's a lot of things running
[00:14] in memory that will never be written to
[00:16] disk if we want to be able to extract
[00:18] things that were not saved to disk they
[00:20] might still be in memory we use it a lot
[00:22] for malware analysis and personally i
[00:24] use it a lot to reconstruct user
[00:26] activities so to install volatility 3 on
[00:28] windows we need a couple of things first
[00:30] off we need python3 go to python.org go
[00:33] to downloads and make sure you're
[00:34] downloading python 3 and installing
[00:37] python is very easy i'll have the links
[00:39] for all of these below next you'll need
[00:41] git for windows you've been watching my
[00:42] channel for a while i download a lot of
[00:45] these forensic tools using git and
[00:47] knowing how to use git is very handy for
[00:50] digital investigators go to
[00:51] getforwindows.org click download run the
[00:54] installer and then you will have git for
[00:55] windows installed in your system the
[00:57] next thing we're going to need is the
[00:59] visualstudio.microsoft.com visual studio
[01:01] cpp build tools this is to build python
[01:05] modules that way we can run volatility
[01:07] click download build tools and then
[01:09] follow the installer and the c plus
[01:11] build tools should install next is the
[01:14] volatility foundation so
[01:15] volatilityfoundation.org
[01:17] you can go to downloads and then if you
[01:20] click on volatility 3 tab you'll notice
[01:22] that they have volatility 3 but it's
[01:24] version 1 the python 3 rewrite so
[01:27] instead we want to go to the github
[01:29] release page this is at github.com
[01:32] volatility foundation volatility 3 and
[01:35] then we can see the code and you notice
[01:37] that under the releases tab we have
[01:39] volatility 3 2.0 so this is actually an
[01:42] updated version and they haven't updated
[01:43] the link on their website so this is why
[01:45] i prefer getting everything directly
[01:47] from github and then even volatility 3
[01:50] 2.0 was released in january but they've
[01:52] had updates since then so i want to work
[01:55] with this development branch directly
[01:57] that way i can get all of the features
[01:59] that are currently available so assuming
[02:01] that you've already gotten python you
[02:02] have git you have microsoft c plus plus
[02:05] installed we're now at the volatility 3
[02:07] github i'm going to click the code
[02:09] button
[02:10] and copy the https url then i'm going to
[02:13] open powershell for now i'm going to
[02:16] go to my desktop and i'm going to clone
[02:19] the volatility code into my desktop so i
[02:21] will do git clone
[02:24] right click and then it'll copy that
[02:26] whole url hit enter and then we'll
[02:29] download the current version of
[02:30] volatility now if i want to update
[02:33] volatility in the future all i have to
[02:34] do is type git
[02:36] pull
[02:37] and then rebuild any of the code that's
[02:39] pulled in so this is an easy way to keep
[02:41] your software up to date before i
[02:43] actually build this i need to install
[02:44] one thing and that is the python snappy
[02:46] extension and in windows i had a lot of
[02:48] trouble installing snappy this is really
[02:51] the only place where i could find the
[02:53] wheel file that would actually work for
[02:54] it for me i'm using amd 64. so i want to
[02:57] click on python snappy win amd 64. if
[03:01] you're using a different system make
[03:02] sure you choose the one for for your
[03:04] individual system i'm going to save that
[03:07] file and it's saved into my downloads
[03:09] folder so next let's check that we have
[03:10] python installed so let's type python
[03:12] and then dash capital v
[03:15] and you should get python and then its
[03:17] version number that you have installed
[03:19] make sure that the first number is at
[03:20] least a three now if we have python
[03:22] installed i'm gonna type pip install and
[03:24] then i'm going to give the full path to
[03:27] where i downloaded the
[03:29] snappy.whl or the wheel file python will
[03:32] install this wheel file directly i
[03:35] already had it installed so everything's
[03:36] okay you shouldn't really get any errors
[03:38] if everything went well so next i have
[03:40] on my desktop the volatility 3 folder so
[03:43] i'm going to cd volatility3 type ls or
[03:47] dir and then you should see a list of
[03:50] all of the files inside the volatility 3
[03:52] folder i have val.pi so i know this is
[03:54] the right folder what we need to do now
[03:56] is install all the requirements to run
[03:58] volatility you can do requirements
[04:01] minimal and it will stall fewer things
[04:03] you need to download fewer things but if
[04:05] you want all of the features of
[04:06] volatility you should do
[04:08] requirements.txt which i recommend so
[04:10] what we need to type inside the
[04:13] three folder we type
[04:15] pip
[04:16] install dash r
[04:18] requirements
[04:20] dot txt pip install dash r
[04:23] requirements dot txt press enter and
[04:26] then what should happen is everything
[04:27] will go through and check if everything
[04:29] is installed if you don't have a package
[04:32] that's already been installed it will
[04:33] try to download the package and compile
[04:36] it so this is where installing the
[04:37] microsoft c plus plus build tools is
[04:39] really important if this is not
[04:41] installed properly you might have errors
[04:43] at this stage so if you do have errors
[04:45] go back and check that microsoft build
[04:47] tools are installed properly so we see
[04:49] if everything was installed correctly by
[04:51] running pythonvol.pi inside the
[04:54] volatility 3 folder so python vol.5 and
[04:58] then dash lowercase v so for python to
[05:02] check the version it was an uppercase v
[05:04] for volatility it's a lowercase v now
[05:07] whenever we run this we see a couple of
[05:08] things we have the volatility three
[05:10] framework and then the version of this
[05:12] is 2.0.2 so this is volatility three
[05:15] version two zero two so it is newer than
[05:17] the most recent release that we saw and
[05:19] then i have a couple of things here for
[05:21] example the symbols path is interesting
[05:24] this is where any symbols will be
[05:25] downloaded for analysis and we can
[05:27] download additional symbols if we need
[05:29] to as well as where the plugins can be
[05:32] installed so volatility does have a lot
[05:34] of plugins that are separate that you
[05:36] can install into these main packages
[05:38] this is the location folder where you
[05:40] would want to install those plugins if
[05:42] that ran then volatility is at least
[05:44] working it's just installed in the
[05:46] volatility 3 folder which is fine if
[05:48] that's where we want to run it from so
[05:49] the next thing we need to do is actually
[05:51] get a memory image so i'm going to open
[05:53] up and i have a folder on my z drive
[05:56] called memory image and the image that
[05:58] i'm going to be analyzing today is the
[06:00] actf
[06:02] dot mem so i need to get the location of
[06:05] my memory image z drive memory image
[06:08] actf dot mim and then the first thing we
[06:10] normally want to do is run python ball
[06:13] dot pi
[06:14] dash f this is the file that we're going
[06:16] to be analyzing i'm going to paste in
[06:19] memory image and then the ac tf dot mem
[06:23] so python vol.pi dash f
[06:26] and then wherever your memory image is
[06:29] located and then we want to get the
[06:31] information about this memory image so
[06:34] i'm going to run windows dot info
[06:37] volatility 3 is a little bit different
[06:39] in that the plugin that we're using is
[06:41] specified at the end here like i'm
[06:43] analyzing windows and i want to get the
[06:45] info for windows i'll show you how to
[06:47] use this as a filter shortly so let's go
[06:49] ahead and run that so now it's scanning
[06:51] through the memory image and this will
[06:53] take a little bit we get some basic
[06:54] information here about the system itself
[06:57] all this is read from memory so for
[06:59] example we have number of processors
[07:01] could be interesting the system time at
[07:03] the time of imaging could be interesting
[07:05] system root was set to c drive windows
[07:07] that could be interesting for the rest
[07:09] of our investigation major operating
[07:10] system version things like that so this
[07:12] is usually the first thing we want to do
[07:14] and if i wanted to run the same command
[07:16] and save the output then i would use a
[07:18] greater than sign and that's piping to a
[07:20] file called actf.mem.info.txt
[07:29] something like that and then i would run
[07:29] it again and then all of this output
[07:30] would be saved into this text file so
[07:33] that way i can use it for later
[07:34] reference so let's say you're starting
[07:35] out with volatility and you have your
[07:37] memory image and you were able to get
[07:39] windows info but you're thinking okay
[07:40] what else can i do with this maybe you
[07:42] don't remember the command that you want
[07:44] to use what you can do is specify your
[07:47] memory image and then specify the plugin
[07:50] that you want to use just as windows
[07:51] instead of saying the entire name just
[07:53] say windows and hit enter and then what
[07:56] this will tell you it'll give you an
[07:58] error and then it will show you all of
[08:00] the different commands that are
[08:01] available right now so everything that's
[08:03] installed that i can currently run on my
[08:05] memory image is here for windows you can
[08:08] do the same for
[08:10] mac os or linux but we're focusing on
[08:12] windows today so these are all the
[08:14] different modules that i can run and
[08:16] then for each of these modules you can
[08:18] also
[08:19] access a help menu which i'll show you
[08:21] shortly and there are some things for
[08:23] example like windows dot mft scan
[08:26] if you have something that looks like
[08:28] this where you have two of the same word
[08:30] volatility automatically tries to search
[08:32] for the most appropriate model so for
[08:33] example if there's only one sub module
[08:36] called mft scan then all you have to do
[08:39] is type
[08:40] windows.mftscan but for example windows
[08:43] registry has multiple modules underneath
[08:47] it so in that case you would have to
[08:48] actually type out windows registry hive
[08:51] scan that way it doesn't get confused
[08:53] with windows registry user assist so my
[08:55] point here is you don't necessarily need
[08:58] to type out the entire thing you can
[09:00] type out the unique module name and then
[09:02] volatility will type the rest for you
[09:04] essentially it seems a bit silly now but
[09:06] it will save you time later so one of
[09:07] the first things we usually do or at
[09:09] least one of the first things i usually
[09:11] do whenever i'm analyzing memory i want
[09:13] to see a process list so that is the
[09:16] windows.pslist
[09:19] module and then i'm going to pipe that
[09:22] into
[09:22] more so i am in powershell in windows
[09:25] and more is usually a linux command line
[09:28] tool but powershell also supports the
[09:30] more anything yellow is a command the
[09:32] powershell understands i'm going to
[09:34] print out all the processes that were in
[09:36] windows at the time of imaging and i'm
[09:37] going to use more so that way it doesn't
[09:39] go by really quickly so let's go ahead
[09:40] and hit enter so now we have process the
[09:43] process list coming out and you can see
[09:45] that i have more here with more if i hit
[09:47] the space bar then it will go to the
[09:49] next page
[09:50] if i don't use more then you're just
[09:51] gonna have all this text flying by and
[09:53] you won't be able to see any of it so
[09:56] from this process list i can see for
[09:58] example first we have the process id
[10:01] that would be this number four here we
[10:02] have the parent process id in this case
[10:05] we have a zero we have the image file
[10:07] name which is the name of basically the
[10:09] executable the offset where it was found
[10:11] in the memory image the number of
[10:13] threads that are currently running the
[10:15] number of handles which could be for
[10:17] example file handles creation time exit
[10:19] time and then file output what i'm
[10:21] usually interested in is image file name
[10:24] that way i can filter and focus on
[10:26] programs that i'm interested in their
[10:28] process id and the parent process id
[10:32] as well as sometimes how many threads it
[10:34] has but many times what handles are
[10:38] available so i tend to focus on things
[10:41] like what files is this process
[10:43] accessing at the time and that's where
[10:45] handles would come in the most
[10:46] interesting if we take this system
[10:48] process we have a process id of four and
[10:51] then the parent process id is zero well
[10:53] why is that system is effectively one of
[10:55] the first processes that are started
[10:57] right and then everything else is
[10:58] started by system so you can see that we
[11:01] have zero meaning that it's one of the
[11:03] first processes it's process id is four
[11:06] and then here we have the registry was
[11:08] opened by process four and the
[11:11] registries process id is 108
[11:15] sms.exe was also opened by process 4 and
[11:18] its process id is 396. so using this
[11:22] we can basically reconstruct how
[11:24] applications were opened who were the
[11:26] parents like where are they coming from
[11:29] okay so this gets really interesting
[11:31] whenever we're trying to find out how
[11:32] different programs were executed so we
[11:35] need to know the process id of the
[11:37] process we're interested in and then
[11:38] very often it's interesting to know the
[11:40] parent process id as well so again i
[11:42] tend to focus on process id sometimes
[11:45] parent process id definitely file name
[11:47] because i want to filter using that
[11:50] sometimes the threads and then many
[11:51] times for me many times handles if
[11:54] you're doing something like malware
[11:55] analysis this might be very different
[11:57] i'm usually use looking at user
[11:59] activities you can see that as we go
[12:01] down there's a lot of processes that
[12:03] we're running at the time if we know
[12:05] what process we're interested in we need
[12:07] to be able to filter this out so i could
[12:10] just dump this entire process list and
[12:11] then search through it but if i'm
[12:13] already interested in a specific process
[12:15] then i can hit q to get out of the more
[12:18] and then instead of more i can use
[12:19] powershell's built-in string searcher
[12:22] select string now select string is not
[12:25] part of volatility it's just kind of
[12:27] helping me to filter so let's say that
[12:30] i'm interested in anything in this
[12:32] memory image related to the chrome
[12:34] browser so i'm going to type chrome so
[12:37] here we still have python volatility.pi
[12:40] our image file
[12:41] actf.mem that's my actual data i'm
[12:44] listing all of the process list but it's
[12:46] so big i want to filter it so i'm going
[12:48] to use a pipe which is an up and down
[12:50] bar for me that's above the enter key
[12:54] and then i use the powershell command
[12:56] select dash string and it has to be
[12:58] capitalized and then i'm searching for
[13:01] chrome now what i would do in linux is
[13:03] basically the same command except select
[13:05] string would be grep and i would be
[13:07] grepping for chrome whenever we do that
[13:09] i hit enter and then you can see that we
[13:11] still had quite a few
[13:13] quite a few processes but all of these
[13:15] are related to chrome.exe so now we can
[13:17] focus in our investigation on chrome.exe
[13:20] and it looks like one of the first
[13:21] processes is
[13:22] 1328. so the parent id of all of these
[13:26] processes is 1328. if i want to focus on
[13:29] the parent chrome process then
[13:32] 1328 is the process that i'm going to be
[13:35] focusing on so using volatility with
[13:38] filtering tools like select string can
[13:40] help you focus in really quick on
[13:41] certain keywords that you might be
[13:43] interested in what we're really
[13:44] interested in is the process id that way
[13:47] i can use the id as a filter whenever i
[13:49] do other things so let's go ahead and
[13:51] see what files chrome is currently
[13:54] accessing so instead of using
[13:56] windows.pslist
[13:58] i'm going to use windows dot
[14:01] handles
[14:02] and then maybe i don't know how to use
[14:04] handles so i'm going to type dash h to
[14:07] give me a help menu for windows handles
[14:10] okay and our option here for
[14:12] windows.handles we can give it a process
[14:15] id i need to do dash dash pid if i want
[14:18] to specify a process id otherwise it
[14:20] will give me all of the file handles in
[14:22] the memory image and again it's going to
[14:24] be a lot of data so if i just want to
[14:26] focus it on chrome
[14:28] now we have chrome's process id of 1328
[14:32] so i can specify the process id and we
[14:34] will just get those handles so let's go
[14:36] ahead and do that
[14:38] dash dash pid
[14:41] 1328
[14:44] and then i'm going to pipe this into
[14:46] more again because i expect a lot of
[14:48] data
[14:49] we have the pid we have the process the
[14:50] offset in memory handle value and the
[14:53] type which we'll use in a second so
[14:55] let's say that we have these event types
[14:57] i o completion type let's go ahead and
[15:00] scroll down a little bit we can see that
[15:02] this has a full path to a file and the
[15:06] type is specified as file we also have a
[15:08] key type which is related to the windows
[15:10] registry so that could be interesting
[15:12] for me as well but for now i'm
[15:14] interested in the file type so i'm going
[15:16] to use the select string keyword again
[15:18] instead of more i'm going to type select
[15:21] string and i'm looking for file so i'm
[15:25] going to pipe that into more notice that
[15:26] the the volatility command is exactly
[15:29] the same i'm printing out all the
[15:31] handles
[15:32] for pid 1328 i'm just filtering based on
[15:36] whether it is a file or not so here we
[15:38] have our file and we can see the file
[15:40] that was accessed we also have a
[15:42] registry key in here because the image
[15:44] file name matched our search query we
[15:47] have a dat file basically all the files
[15:50] that it was accessing but not all of
[15:51] these are going to be interesting maybe
[15:53] the ones that include for example john
[15:55] doe our user might be interesting for us
[15:58] or maybe we're only interested in
[15:59] databases so let's go ahead and change
[16:02] our query again let's add another filter
[16:05] i'm going to select
[16:07] string
[16:08] and i'm going to search for history
[16:11] because i know that chrome has a history
[16:13] file so notice i'm taking the output of
[16:15] volatility i haven't changed that
[16:17] command at all i'm piping that into a
[16:18] keyword search filter for file filtering
[16:21] out everything that's not a file and
[16:23] then i'm piping that into another
[16:25] keyword for history so i'm looking for
[16:27] any file that has the word history in it
[16:30] and then i pipe that into more and we
[16:32] see what we get here okay so we have a
[16:33] couple different files here so we have
[16:36] what looks like three files were
[16:38] returned
[16:39] one is the history journal one is media
[16:41] history and then one is the history file
[16:44] so actually this history file looks very
[16:46] interesting if i want to
[16:48] understand john's chrome browser history
[16:52] i know that i'm interested in this file
[16:53] and i want to analyze his browser
[16:55] history you take the address specified
[16:57] for this file and then i have my basic
[17:00] volatility command this really isn't
[17:01] going to change ever and i'm going to
[17:03] specify an output directory i want to
[17:05] output the file but before i can output
[17:07] the file i need to create an output
[17:09] directory so i'm going to make
[17:11] dir mkdir a folder called dump
[17:17] okay so now i've created a folder called
[17:19] dump and that's where i'm going to save
[17:21] everything that i'm carving out of this
[17:23] memory image we can go back to our
[17:24] volatility command and i need to do dash
[17:26] o
[17:27] to specify the output directory i'm
[17:30] going to say save it into the dump
[17:33] folder
[17:34] and then i'm going to use the command
[17:36] windows.dump
[17:38] file
[17:40] and then i'm going to specify the pid of
[17:44] 1328 which is our chrome process
[17:48] and in that chrome process i have the
[17:50] virtual address
[17:52] that we just copied okay
[17:54] so what i have here is python
[17:57] volatility.pi our memory image that
[17:59] we're analyzing i'm specifying an output
[18:01] directory of dump i'm using the plugin
[18:04] windows dump file to extract a file from
[18:07] that memory image and i want to search
[18:09] by process id for the chrome process
[18:12] and then with the virtual address that
[18:14] we got from uh the file handle so then
[18:18] this should output
[18:19] a
[18:20] history file for us into the dump folder
[18:24] so let's go ahead and press enter a file
[18:25] was created the history.dat and we see
[18:29] the history.dat file was created here
[18:31] okay so now we have the history file.dap
[18:34] i have
[18:36] hxd installed so i can just do open with
[18:39] hxd hex editor i recommend you get that
[18:42] if you're going to be analyzing any type
[18:43] of binary data let's go ahead and open
[18:45] it and at the beginning of this we see
[18:47] sql lite format 3 which means this is an
[18:50] sqlite file probably an
[18:53] sqlite file
[18:54] if we scroll through here we see some
[18:57] urls we see some information so actually
[18:59] this does look like a chrome history
[19:02] file
[19:03] i would get some sort of sqlite viewer
[19:05] now to view this if i instead of using
[19:07] the hex editor now that i know that it
[19:09] is an sqlite formatted file that's how
[19:12] we can find for example an individual
[19:14] file inside a process and then dump that
[19:17] directly from memory is using the
[19:19] windows dump file
[19:21] with our pid give it the virtual address
[19:23] of the file we're interested in and the
[19:25] output directory what you can also do is
[19:27] dump all of the files in this memory
[19:29] image for a particular process id just
[19:31] don't specify the address of the file so
[19:34] here we have windows dump file
[19:36] i still have the output dump directory
[19:38] and i specify the pid let's go ahead and
[19:40] press enter this is going to give us a
[19:42] lot of files that we're not necessarily
[19:44] interested in okay it's just going to
[19:45] dump every file related to that process
[19:48] id so i usually just dump one file at a
[19:51] time as i realize that i need it maybe
[19:53] i'm going to dump every file related to
[19:55] a process and then do a virus scan of
[19:57] the files for example so that could be
[20:00] you know a way to automate
[20:02] analysis of a specific process whether
[20:04] you want to dump everything or focus on
[20:06] a specific file i tend to focus on files
[20:08] but if you're doing a bulk scanning then
[20:11] maybe it's interesting for you another
[20:12] thing that tends to be interesting is
[20:13] the windows cmd line command
[20:17] and i want to pipe this into more
[20:19] because it's usually quite a bit of data
[20:20] this shows command line usage but more
[20:23] than that it shows switches that were
[20:25] used whenever programs were started so
[20:28] we have a couple different programs here
[20:30] and and for example we can see the
[20:32] switches that were used to launch these
[20:35] programs so
[20:37] just looking at the windows registry for
[20:40] example we might see the
[20:41] svchost.exe was run
[20:44] we might see the entire executable but
[20:46] we wouldn't necessarily see the options
[20:48] that it was ran with so if somebody was
[20:50] running something from the command line
[20:52] in other places you might just see that
[20:54] the the command was ran but you wouldn't
[20:56] see all of the options that was ran with
[20:59] it this is a really quick way to see
[21:01] what's been run
[21:02] where things were run from
[21:04] and if they had any special options
[21:06] while they were running for example at
[21:08] the very bottom here we have ftk imager
[21:10] that was ran to create this disk image
[21:12] and it was run from the e drive okay so
[21:16] everything else pretty much was run from
[21:18] the c drive as we would expect for like
[21:20] system options but in this case we had
[21:22] ftk imager ran from e drive and it looks
[21:26] like imager light was ran so maybe
[21:28] that's an you know an external usb stick
[21:30] like where is that drive coming from so
[21:33] if we saw you know a malicious
[21:35] executable ran from an e drive then
[21:38] maybe somebody came in
[21:40] plugged in a usb stick
[21:42] installed a virus and then plugged out
[21:44] the usb stick that's possible so so
[21:46] checking command line might be
[21:48] interesting for that next something that
[21:50] i pretty much always run along with
[21:52] process list would be net stat
[21:56] and it's going to give me a lot of stuff
[21:57] so i'm going to pipe it into more so
[21:59] what we get here is the offset in the
[22:01] memory image uh the protocol that was
[22:03] used the local address of the computer
[22:06] that this memory image was taken from
[22:08] and then the local port the foreign
[22:11] address or the external address that
[22:14] we were connecting to
[22:15] and then the foreign port that was
[22:17] connected so let's say that we're
[22:18] interested in chrome.exe this is our
[22:21] local address that chrome was running on
[22:23] and then it was connecting to the
[22:25] address
[22:26] 185 70 41 35 well now we can just go and
[22:30] do a quick search it comes back to
[22:33] proton ag so
[22:35] protonmail.ch so
[22:37] at least from this we very quickly find
[22:40] out that the user either was connected
[22:42] to protonmail at the time of imaging or
[22:44] had just closed it so now protonmail is
[22:47] interesting
[22:48] for the case because we have a
[22:50] connection back to protonmail we can go
[22:52] through and check all of these ip
[22:54] addresses and see where they're calling
[22:56] back to and it might give us some really
[22:58] interesting information about you know
[22:59] malware that was installed if it's
[23:01] calling back home how it was calling
[23:02] back home
[23:04] or just user activities like for example
[23:06] this address is protonmail
[23:08] most of these are probably calling back
[23:10] to protonmail related to chrome so
[23:12] finding out network connections we're
[23:14] also interested in the name of the
[23:15] process and the process id this is how
[23:18] we can go back and see the process list
[23:21] what things are running what is it
[23:22] connecting to what files is it opening
[23:25] and then also what kind of network
[23:27] connections is it making so again if i'm
[23:29] only interested in chrome then i can do
[23:32] the same search again select
[23:35] string chrome
[23:40] and then that will filter out everything
[23:40] that's not related to chrome so that way
[23:42] i can focus my investigation on only
[23:44] addresses that chrome was accessing for
[23:47] example use filtering often another
[23:49] thing that's useful especially if you're
[23:50] trying to investigate a certain suspect
[23:53] and you want to know their password and
[23:54] then maybe how that password is used on
[23:56] other systems we want to do hash dump
[23:59] what this will do is output the password
[24:01] hash values for this window system so
[24:04] let's take a look at that so once we
[24:05] have those hash values then we can try
[24:07] to crack the hash values get the
[24:09] password for the user there so for
[24:11] example john doe now we have the
[24:13] password hash if we can crack that
[24:15] password hash then maybe that password
[24:18] is used on other systems or maybe
[24:21] you know it'll give us some insight into
[24:22] how the user is actually coming up with
[24:25] their passwords so getting those
[24:26] passwords gives us potentially access to
[24:29] another local system if the password was
[24:31] being used maybe the passwords used in
[24:33] online accounts so doing a hash dump
[24:35] getting the password hash and then
[24:37] trying to crack that password hash can
[24:39] really help us in the investigation to
[24:41] uncover more data and then another thing
[24:43] that i tend to use a lot whenever i'm
[24:45] dealing with windows is windows registry
[24:47] analysis one of those is the
[24:49] user assist so we can do registry
[24:57] registry user assist and i'm going to
[24:57] use the dash h just to see if we have
[24:59] any options we have the hive offset
[25:01] option if i want to focus on that or we
[25:03] don't have to put it and everything in
[25:05] user assist will be shown so i'm just
[25:07] going to run this again with more
[25:10] and user assist tells us a lot of
[25:11] interesting things about user activities
[25:13] in the system so for example we have the
[25:16] hive offset the hive name where we're
[25:18] getting all this from last write time so
[25:20] this is essentially you can almost think
[25:22] of it like the last time that an action
[25:25] took place related to that key so if
[25:27] it's related to a program then that
[25:29] might be the last time that the user ran
[25:31] that program
[25:32] we also have the count which is the
[25:34] number of times the the program was run
[25:37] the focus count so the number of times
[25:39] that the user focused on that particular
[25:42] window for the program and then the time
[25:44] focused is the total amount of time that
[25:46] the user was looking at that over time
[25:48] not in an individual session you got to
[25:50] be a little bit careful with count focus
[25:52] count and time focus don't take it as
[25:54] 100 accurate but it can still establish
[25:57] that for example the user
[25:59] did open up this program and did
[26:02] focus on it for a particular period of
[26:03] time okay so let's go ahead and see what
[26:05] that looks like so for example here i
[26:07] have ms
[26:09] was executed and it seems like it was
[26:11] executed seven times it was the focus
[26:14] seven times and then it had a total
[26:16] focus time of like one minute so
[26:18] basically it was open several times but
[26:20] not really accessed here's another one
[26:22] microsoft edge the browser it was opened
[26:25] three times and then it was the focus 16
[26:28] times which means the user kind of went
[26:30] away from the browser and then came back
[26:32] to it so focused on it and the total
[26:34] focus time was about an hour 50 minutes
[26:36] 56 seconds or so so this establishes
[26:39] that they at least were using microsoft
[26:41] edge uh they'd focused on and away from
[26:44] it several times and they'd use it for a
[26:46] considerable amount of time are these
[26:48] 100 accurate maybe not but this is
[26:50] already a really good place to start
[26:52] user assist is really interesting for
[26:54] investigations especially to establish
[26:56] user behaviors and whether programs were
[26:58] used how long they were used things like
[27:00] that and again you can use the same
[27:02] filtering technique that we've been
[27:03] using to focus in on for example
[27:05] microsoft edge chrome whatever it is
[27:08] that you're that you're looking for but
[27:09] sometimes you might want to find and
[27:12] list all of the registry hives that are
[27:14] available in the system and then we
[27:15] might want to carve them out for example
[27:17] so using that we can use hive list so
[27:21] windows.registry.hivelist
[27:23] let's see if there's any options for
[27:25] that we have a filter so string to
[27:28] filter hive names returned and then dump
[27:30] extract listed registry hives if we just
[27:32] run it without any options then we get
[27:35] all of the registry files that we could
[27:36] find let's say that we're interested
[27:38] though in john doe so let's try to
[27:41] filter by john
[27:43] okay and then we only get back anything
[27:44] that looks like a registry file related
[27:46] to john doe in the string so basically
[27:49] we're using volatility to do the keyword
[27:51] searching for us
[27:52] and let's say that i'm actually
[27:54] interested in nt user dot dat
[27:57] so let's do a filter for doe slash nt
[27:59] user dot dat
[28:00] do slash nt user.dat
[28:03] so now we're focused on the file that we
[28:05] want so let's go ahead and dump
[28:11] and just like before we need to specify
[28:11] an output directory i'm going to put
[28:13] that into the dump folder
[28:16] windowsregistry.hivelist filterdo slash
[28:19] ntuser.dat and then dash dash dump
[28:23] and then if we go check our dump folder
[28:25] we have our hive file so i'm going to
[28:26] open that and then we have our registry
[28:28] file header here so i've just dumped
[28:31] john's nt user.dat file so now i can use
[28:34] another program to actually analyze the
[28:36] into user.dat registry file if i need to
[28:39] let's say we don't want to dump the
[28:40] entire registry file i would normally
[28:42] prefer to dump it and then analyze it
[28:44] with a different program but maybe you
[28:45] have a just one specific key you want to
[28:48] check we can use windows registry print
[28:51] key and then let's check the options for
[28:53] that
[28:55] with print key we can have the offset to
[28:57] the hive the key that we're looking for
[28:59] and then recurse so recurs through all
[29:01] of the keys if we're at like a top level
[29:04] so what i want to do is print key
[29:07] and then i'm going to give it a key
[29:08] value and a key that we very very
[29:10] commonly use is software
[29:12] microsoft
[29:14] windows
[29:16] current version
[29:20] okay and then i'm going to pipe that
[29:20] into more because it's going to be a lot
[29:22] now we're listing all of the keys inside
[29:24] current version we're not necessarily
[29:26] getting the values because we haven't
[29:27] gone low enough if we actually wanted to
[29:29] go lower then we could do something like
[29:30] dash dash recurse
[29:33] and then that will actually go into each
[29:35] of the key directories and then look for
[29:38] the value pairs so recurse and then i'm
[29:40] going to pipe this into more as well we
[29:42] can see the key and then inside that key
[29:44] we can see the values that are
[29:45] associated with this so this reg binary
[29:47] and then we actually have the data here
[29:49] if you know exactly the key that you're
[29:51] looking for and you only have one or two
[29:52] to search for or if you write a script
[29:55] and want to print out specific keys then
[29:57] you can use the print key option inside
[30:01] volatility by far i use user assist the
[30:03] most with a search filter or i use hive
[30:06] list dump the hive that i'm interested
[30:08] in and then process it with a different
[30:10] tool but that's my workflow
[30:12] if you know exactly what key you're
[30:13] going for and you don't have too many
[30:14] keys to search for then it totally makes
[30:16] sense to use print key so with that
[30:18] we've shown how to install volatility
[30:20] and keep it updated inside a git
[30:22] repository we've shown how to process a
[30:24] ram image with volatility we've gone
[30:26] through how to do things like get the
[30:28] memory image we've listed processes
[30:31] we've listed file handles we were able
[30:33] to extract files from memory using dump
[30:36] files we were able to see command line
[30:37] options we were able to see the network
[30:39] we could dump windows password hashes
[30:42] that we can later crack if we need to we
[30:44] were able to query the user assist in
[30:46] the windows registry and then try to
[30:48] find programs that were accessed and how
[30:50] much they were accessed we were able to
[30:52] both list all of the hives that are
[30:54] available in the memory image as well as
[30:56] focus on a specific hive and dump it
[30:59] using the hive list function and then we
[31:02] were also able to focus in on a specific
[31:04] registry key using the print key tool if
[31:08] you can basically list processes you
[31:10] understand how to dump a file
[31:12] you can access the windows registry and
[31:14] do some searching through it or at least
[31:15] dump a registry hive then you can
[31:18] already do a lot of things with memory
[31:20] okay now there's a lot more we can do
[31:22] with this there's really advanced stuff
[31:24] that volatility can do there's a lot of
[31:26] extra plugins that volatility has but if
[31:29] you can at least
[31:30] list processes list networks
[31:32] dump files look through the windows
[31:34] registry you already have a great start
[31:36] to using volatility you just need to get
[31:38] used to the way that the commands work
[31:41] and everything else will be easy from
[31:43] there so that's it for this introduction
[31:44] to volatility 3 i hope that was useful
[31:46] thank you very much
