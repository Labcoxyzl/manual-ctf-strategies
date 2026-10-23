# Introduction to MFTECmd - NTFS MFT and Journal Forensics

Source: https://www.youtube.com/watch?v=_qElVZJqlGY

English caption extraction; automatic captions may misrecognize commands. Rolling duplicate lines removed.

[00:07] welcome to 13
[00:07] cubed in this episode we're going to
[00:09] take a look at a tool from eric
[00:10] zimmerman called
[00:11] mfte cmd which can help us parse the
[00:15] ntfs
[00:16] mft or master file table and file system
[00:19] journals
[00:20] but first let's take a step back and
[00:22] review some important concepts relating
[00:24] to file system journaling
[00:26] now if some of this sounds familiar to
[00:28] you we actually covered much of this in
[00:30] a previous
[00:31] 13 cubed episode called ntfs journal
[00:34] forensics but
[00:35] even if you've watched that stay with me
[00:37] because this episode will cover many of
[00:39] those concepts in more detail
[00:41] firstly though what is file system
[00:44] journaling
[00:45] well at a high level it's a
[00:46] transactional record of all the changes
[00:48] made
[00:48] to a volume in the event of a crash or
[00:51] power failure
[00:52] the operating system can use the
[00:54] information stored in these journals to
[00:56] roll back or undo changes and pick up
[00:59] where it left off
[01:00] the overall goal is to maintain the
[01:02] integrity of the file system and to
[01:04] hopefully prevent catastrophic events
[01:06] from occurring
[01:08] in that previous episode i mentioned we
[01:10] used advanced ntfs
[01:12] journal parser or anjp to look at this
[01:16] information
[01:17] but as of this recording that tool is no
[01:19] longer available
[01:20] many of you reached out to me asking if
[01:22] i knew of a suitable alternative
[01:24] which is what prompted me to make this
[01:26] episode
[01:28] so we're going to be looking at mfte cmd
[01:30] which can help us
[01:31] parse some of these artifacts and fill
[01:34] the void
[01:35] if this is your first time taking a look
[01:37] at this though you may be wondering
[01:39] why should i care i mean seriously why
[01:41] is this even forensically relevant to
[01:43] begin with
[01:45] well the answer is it's because we can
[01:46] use the journals to find evidence of
[01:48] things like
[01:48] file creations deletions renames and
[01:52] more
[01:53] the journals may be one of the only ways
[01:55] to prove that a file
[01:56] once existed on a machine even in some
[01:59] cases where anti-forensics was used
[02:02] so it's a big deal the first of the two
[02:05] journals we're going to talk about
[02:07] is called the usn journal the actual
[02:10] file is dollar usn jrnl
[02:13] and it's stored under the dollar extend
[02:16] directory
[02:17] there's actually a couple of alternate
[02:18] data streams within
[02:20] dollar usn jrnl and they are dollar j
[02:23] and dollar max but it's
[02:24] dollar j that contains the meat the
[02:26] actual data we're after
[02:29] dollar j is stored as a sparse file
[02:32] so it can appear to be multiple
[02:33] gigabytes in size
[02:36] now when you think of usn journal think
[02:39] high
[02:39] level changes this provides an efficient
[02:42] change monitoring solution so
[02:46] it may come as no surprise that backup
[02:49] or
[02:49] antivirus software can use this to
[02:52] monitor
[02:52] changes or deltas to files
[02:56] the information unfortunately may only
[02:59] last days
[03:00] to weeks on busy systems
[03:03] the typical size is 32 megs
[03:07] and some example operation codes or op
[03:10] codes associated with
[03:11] usn journal are things like file create
[03:14] file delete rename old name and so on
[03:18] pretty sure that just by the name alone
[03:20] you can determine what those things
[03:22] mean like what do you think file delete
[03:24] means
[03:26] all right now let's talk about dollar
[03:28] log file
[03:30] dollar log file is located in the volume
[03:32] root so it's not
[03:33] inside of that dollar extend directory
[03:36] now this one tracks detailed low-level
[03:40] transactional changes for ntfs
[03:44] it provides file system integrity and
[03:46] resilience
[03:47] and it records the actual data that
[03:49] changed
[03:50] but it may only last hours to days on
[03:53] the primary boot drive
[03:55] the typical size is 64 megs and some of
[03:59] its example operation codes include
[04:01] things like
[04:01] add index entry allocation initialize
[04:04] file records segment etc so just
[04:08] by the names of the op codes alone you
[04:10] can see that it sounds more detailed
[04:12] right
[04:13] and there are also more opcodes
[04:15] associated with this journal
[04:16] which makes sense because as i said
[04:19] dollar log file
[04:20] is more detailed and low level whereas
[04:23] dollar usn journal
[04:25] is high level
[04:28] so the both of them together as you saw
[04:30] don't have extremely long
[04:32] life spans but fortunate for us we can
[04:35] sometimes use
[04:36] volume shadow copies to extend that
[04:39] event horizon
[04:40] in other words we can pick these
[04:41] journals out of volume shadows that may
[04:44] exist on the system and pull this
[04:46] historical data
[04:48] this could provide increased visibility
[04:50] over weeks or maybe even months
[04:52] if you're lucky all right so you're here
[04:56] for the demo
[04:56] it's one thing to look at some text on a
[04:58] slide but it's a whole other thing to
[05:00] see it
[05:01] in action and this is what you guys are
[05:03] looking for
[05:04] so we're going to be using cape to
[05:06] acquire the ntfs
[05:08] master file table or the mft and
[05:11] the journals we're then going to use
[05:13] mfte cmd
[05:15] to parse the mft and the usn journal
[05:18] but wait a minute what about the dollar
[05:21] log file
[05:22] did i mess up and leave it off the slide
[05:25] no
[05:26] and the reason for that is because as of
[05:27] this recording mfte
[05:29] cmd does not yet parse dollar log file
[05:34] it will in the future but as i'm
[05:36] recording this it does not
[05:37] when you look at the help associated
[05:39] with mft ecmd you'll actually
[05:41] see dollar log file listed as an option
[05:44] but again it's
[05:44] not here yet we'll then analyze the
[05:48] results in
[05:49] timeline explorer which if you've
[05:50] watched 13 cubed episodes before you'll
[05:52] know it's one of my favorite forensics
[05:54] tools
[05:55] and that's pretty much it so let's get
[05:58] started
[06:00] okay we're in the windows 10 virtual
[06:02] machine that we're going to be using for
[06:04] the demo and you'll notice that i have
[06:05] an explorer window
[06:06] opened and we're looking at the tools
[06:08] cape directory
[06:10] these are the files that are part of a
[06:11] normal cape distribution
[06:13] you'll see the directories documentation
[06:15] modules targets
[06:16] and a few files including the cape
[06:18] binaries themselves
[06:20] but what i want to draw your attention
[06:21] to is the targets directory
[06:23] because i want to talk to you about how
[06:25] we're going to grab the forensic
[06:27] artifacts that we're after
[06:29] if we take a look at the targets we're
[06:31] going to find that there are
[06:33] several pre-existing ones that will help
[06:35] us grab these artifacts
[06:36] so if i open this up within this
[06:38] location you're going to see
[06:40] several different directories that
[06:42] nicely organize the types of targets
[06:44] that we have
[06:46] and if we take a look at the windows
[06:48] directory that's the first thing i want
[06:49] to draw your attention to because there
[06:51] are three cape targets
[06:53] in this location that i'll highlight
[06:54] here for you that's
[06:56] dollar j dollar log file and dollar mft
[06:59] those are the three files that make up
[07:01] the trifecta of what we're after
[07:04] the same three files that we'd used in
[07:06] the anjp
[07:07] utility in that previous 13 cubed
[07:09] episode but as mentioned
[07:10] dollar log file as of this recording is
[07:13] not yet supported by mft ecmd
[07:15] nonetheless it wouldn't hurt to grab it
[07:17] anyway because at some point
[07:19] the tool will support that artifact but
[07:21] check this out
[07:22] let's go back and go into the compound
[07:24] directory here
[07:25] as it sounds compound would be a target
[07:28] that is made up of
[07:30] other targets a target of targets if you
[07:32] will
[07:33] and if you look at this one you'll see
[07:35] one named filesystem.tcape
[07:38] hmm i wonder what's in there well let's
[07:40] go ahead and open it up
[07:42] at the top you'll see the standard
[07:43] metadata that's part of any cape
[07:45] target or module configuration file but
[07:48] check this out below that the first
[07:51] three artifacts that we see
[07:52] are dollar mft dollar log file and
[07:55] dollar j
[07:56] again dollar j is that alternate data
[07:58] stream that's part of the
[07:59] usn jrnl file that's where the meat of
[08:02] the data
[08:03] lives that we're after so we can just
[08:06] use
[08:07] file system as the cape target that's
[08:10] the bottom line here
[08:11] that's the only target we need to use to
[08:13] grab the artifacts that we're after
[08:14] so let's go ahead and go up to our
[08:16] windows terminal and you'll notice that
[08:17] i have an administrative powershell
[08:19] command prompt opened
[08:20] i'm going to run cape.exe the t source
[08:24] is going to be
[08:24] c colon of course our target as just
[08:28] mentioned will be
[08:29] file system the destination i'm just
[08:32] going to put
[08:32] on this demo user's desktop
[08:36] i'm also going to go ahead and instruct
[08:38] cape to create a
[08:39] vhdx container we do have to specify
[08:42] some kind of identifier for the
[08:43] container here
[08:44] i'll just use demo and by default this
[08:47] will be
[08:48] zipped compressed so again the target
[08:51] source or t source is c colon the single
[08:54] target we are using
[08:55] is that compound target called file
[08:58] system
[08:58] the destination is the desktop we're
[09:01] telling kate to create a vhdx file
[09:04] and it will be zipped by default so as
[09:07] you can see we're off to the races cape
[09:09] is doing its thing
[09:10] and i'm not going to sit here and make
[09:12] you wait on this i'm going to fast
[09:14] forward this
[09:15] and then we'll pick up from there and as
[09:18] you can see this took
[09:19] just over 45 seconds to complete as
[09:22] listed right here all right so we should
[09:25] now have the data
[09:26] on our desktop so let's go ahead and
[09:28] minimize this windows terminal
[09:30] and as you can see we have a couple of
[09:32] files here really it's just the zip file
[09:34] that we're after we do of course have
[09:35] the
[09:36] log but that guy right there is what we
[09:38] need to take and move over to
[09:40] our analysis workstation so that we can
[09:42] continue our demo
[09:43] so let's do exactly that
[09:47] all right i have moved the zip file from
[09:49] the virtual machine
[09:50] onto the desktop of our analysis
[09:52] workstation and you'll see it
[09:54] right over here let's go ahead and unzip
[09:56] this so that we can expose the vhdx file
[09:59] within it
[10:00] so i'll just use the contextual menu
[10:02] option for 7-zip
[10:03] extracting it to its own directory let's
[10:05] go ahead and open this up
[10:07] and there's that vhdx file all i need to
[10:09] do is double-click this
[10:11] and windows should automatically mount
[10:13] it and assign the next available drive
[10:14] letter
[10:15] of f colon in this case if we go into
[10:18] dollar extend you'll see dollar j which
[10:20] is part of the dollar usn jrnl
[10:22] and there's dollar mft those are the two
[10:25] artifacts that we are specifically
[10:27] interested in
[10:28] and of course you'll see the other
[10:29] artifacts available there as well within
[10:31] that vhdx
[10:33] let's pop open the windows terminal you
[10:35] will see that i have an administrative
[10:36] command prompt and i'm in the tools
[10:39] zimmerman directory let's run mfte cmd
[10:42] without any options and go up to the top
[10:44] and take a look at the most important
[10:46] option which is dash
[10:47] f using dash f you can specify that
[10:50] dollar mft or dollar j you will see
[10:53] dollar log file listed even though it's
[10:55] not yet supported
[10:56] at the bottom we have some examples of
[10:58] how to use it but if you've used other
[11:00] zimmerman tools they'll be quite
[11:01] familiar with the syntax
[11:03] pretty straightforward we'll clear the
[11:05] screen and go ahead and
[11:07] point at first the dollar mft
[11:10] so we'll use dash f and we'll point to f
[11:12] colon backslash
[11:14] c slash dollar mft
[11:17] okay so far so good dash dash csv will
[11:20] specify the location
[11:22] into which we would like the csv file
[11:24] created csvf will specify that
[11:27] name of the csv file in this case
[11:29] mft.csv
[11:31] and well that's it that's all we really
[11:34] have to specify
[11:35] now you'll notice that i've pressed
[11:37] enter and this is in real time so i
[11:39] haven't sped this up or anything
[11:40] but while i'm talking it's chewing
[11:43] through that mft
[11:44] and you'll see the processed message
[11:46] showing it took just under nine seconds
[11:49] and it found about 274 000 mft
[11:52] file records so that's it it's written
[11:55] the mft csv file
[11:57] all we have to do now is process our
[12:00] other artifact
[12:01] which is the dollar j file so same deal
[12:04] dash f point to that which is in dollar
[12:07] extend
[12:08] slash dollar j once again we'll use dash
[12:11] dash
[12:12] csv to specify the directory into which
[12:15] we want that csv file written
[12:17] again being the desktop and then for the
[12:20] csvf
[12:20] file name i'll just call this i don't
[12:23] know usnjrnl.csv
[12:26] which is a little more meaningful than
[12:27] just dollar j dot csv or j.csv
[12:31] all right so that's pretty much it
[12:34] there's usn journal
[12:35] it took just over one second to process
[12:39] it pulled out looks like 276 000 entries
[12:44] and that's all there is to running mft
[12:46] ecmd
[12:47] in the final section what we're going to
[12:49] do is grab these csv files
[12:52] pop them open in timeline explorer and
[12:54] take a look at what we have
[12:56] so let's jump into the final section of
[12:58] the demo now
[13:00] we're now in timeline explorer and the
[13:02] first thing i'd like to direct your
[13:03] attention to
[13:04] are the two tabs in the top left you'll
[13:07] notice that we have
[13:08] both csv files opened and we're
[13:11] currently looking at
[13:12] mft.csv so
[13:15] let's start by taking a quick look at
[13:17] the available
[13:18] column headers of which there are quite
[13:21] a few
[13:22] so we have the mft entry and sequence
[13:24] number along with the mft parent
[13:26] entry and sequence numbers we have the
[13:29] parent path
[13:29] and file name which are of course very
[13:31] important the file
[13:33] size and then we have the first of
[13:35] several columns containing
[13:37] timestamps so let's scroll over and take
[13:38] a look at these
[13:40] notice that we have two columns for
[13:42] created
[13:43] two for last modified two for mft
[13:46] last record changed and two for accessed
[13:49] so that is going to be our
[13:51] b m c
[13:55] and a time stamps if you're familiar
[13:57] with the macb
[13:58] nomenclature the ones with hex 10 are
[14:02] our dollar
[14:02] standard underscore information
[14:04] timestamps and the ones with hex
[14:06] 30 are our dollar file underscore name
[14:10] timestamps remember that standard
[14:12] information timestamps are those that
[14:14] are
[14:14] accessible by the windows api that's
[14:16] what you're looking at with windows
[14:18] explorer for example
[14:19] whereas the file name timestamps are in
[14:21] theory only accessible by the windows
[14:23] kernel
[14:24] so often we can compare standard
[14:26] information and file name
[14:27] and if we see a discrepancy there as in
[14:30] this column which does a lot of it for
[14:32] you
[14:32] where the standard information is less
[14:34] than the file name
[14:35] that might be indications of time
[14:37] stopping though not everything that
[14:40] would appear here means it's evil
[14:41] because some of this
[14:42] is naturally occurring behavior on a
[14:44] windows system
[14:45] also notice there is a column for sub
[14:48] second zeros here
[14:49] what that means is because of the
[14:51] extremely high precision
[14:53] used by windows with regards to file
[14:56] system timestamps which
[14:58] by the way is hundreds of nanoseconds to
[15:00] lapsed since
[15:01] january the first 1601 if we happen to
[15:05] see a time stamp
[15:06] with seven zeros in other words the sub
[15:09] seconds are
[15:10] all zeros well that would be a little
[15:12] odd don't you think
[15:14] that can certainly indicate time
[15:15] stopping because what do you think the
[15:17] chances are that a
[15:18] file would have a creation or a
[15:21] modification time
[15:22] that had exactly occurred in the all
[15:27] zeros sub second precision in other
[15:29] words all seven digits were zeros
[15:31] that is probably not going to happen and
[15:34] that in and of itself
[15:35] is behavior that may indicate time
[15:38] stopping occurred
[15:39] so we have two different columns there
[15:41] that can help you quickly
[15:42] look through things that might indicate
[15:44] time stopping
[15:45] one other important thing to note here
[15:47] and you may have already been thinking
[15:48] this as you're watching the video
[15:50] but notice that there are quite a few
[15:52] timestamps that are missing they're just
[15:54] blank
[15:55] well first off the ones that are missing
[15:57] are in the columns with hex
[15:59] 30 at the end which as a reminder are
[16:02] our dollar
[16:03] file underscore name timestamps when you
[16:06] see this
[16:07] it means that the timestamp that would
[16:08] have been in that location
[16:10] is exactly the same as the corresponding
[16:13] time stamp
[16:14] in the adjacent hex 10 column
[16:17] in other words the dollar file
[16:19] underscore name timestamp that would
[16:20] have been there
[16:21] is the same as the dollar standard
[16:23] underscore information timestamp
[16:25] adjacent to it so it's left blank this
[16:28] provides
[16:29] several benefits including a much
[16:31] smaller overall file size
[16:33] but the primary benefit is less noise to
[16:36] have to walk through
[16:37] when looking for entries where the two
[16:39] time stamps don't match
[16:40] so it's just kind of an automatic focus
[16:43] into that area
[16:44] because that implies those time stamps
[16:46] don't match if you see a value there
[16:48] otherwise it would be blank so i just
[16:51] wanted to point that out
[16:52] because that may be a question that you
[16:54] have as you look through this data
[16:56] all right before we move away from the
[16:58] mft let me do a quick search to show you
[17:00] how easy it is to look for something
[17:02] within the mft so under parent path here
[17:04] i'm going to specify the
[17:06] desktop directory for our demo user and
[17:08] you can see that we have
[17:10] four hits the last of which does not
[17:13] have the
[17:13] in use check mark next to it which means
[17:16] it's an
[17:17] unallocated mft entry one that is
[17:19] available for
[17:20] reuse and that's actually from a
[17:22] previous vhdx file that was on the
[17:24] desktop
[17:25] that i since deleted you can see the
[17:27] file size and if we scroll to the right
[17:29] you can see those same timestamp columns
[17:32] that we already covered
[17:34] so very easy to search through the mft
[17:36] to get a snapshot in time
[17:38] view of what was present on the file
[17:41] system
[17:42] all right so now let's go ahead and move
[17:44] over to the usn
[17:46] journal and here the column headers are
[17:49] pretty self-explanatory
[17:50] but there's one in particular that i
[17:52] want to point out to you
[17:54] and that is the update reasons column
[17:58] that's where you're going to find those
[18:00] op codes as you saw
[18:01] in the intro for this episode remember
[18:04] things like file create
[18:05] file delete rename old name rename new
[18:08] name well that's where you'll see those
[18:09] op codes and where you can easily
[18:12] filter on them so pretty neat to be able
[18:14] to know
[18:15] where that is and actually be able to
[18:17] see those specific operations in the
[18:19] journal
[18:20] we could filter for example on file
[18:22] delete and see
[18:23] the files that were deleted all right so
[18:26] let's go ahead and in the top right i'm
[18:29] going to type in apg.exe which
[18:31] is the name of an executable i placed on
[18:34] this demo system
[18:35] it's a password generation utility not
[18:37] that that's important
[18:38] but at the very top you'll see the file
[18:40] create update reason
[18:42] and at the very bottom you see one
[18:43] called rename old
[18:45] name but notice the entry number
[18:49] let's go ahead and filter on everything
[18:51] with that same
[18:52] entry number and get rid of our search
[18:54] now
[18:55] so now we're looking for everything on
[18:57] the file system with that entry number
[19:00] so i'm going to highlight this for you
[19:01] so it'll make more sense but if we
[19:04] scroll all the way to the right here and
[19:05] then all the way down
[19:07] check out the story that can be told
[19:10] with what you're looking at
[19:12] at the very top we have apg.exe and we
[19:15] have a
[19:15] file create update reason and then at
[19:18] the very bottom
[19:19] we have a file delete for demo2.exe
[19:24] so what has happened here well it turned
[19:27] out
[19:28] that what i did was i placed apg.exe
[19:31] onto the file system i then renamed it
[19:35] to demo.exe then renamed that to
[19:39] demo2.exe
[19:40] and then deleted it and everything i
[19:43] just said there
[19:44] can be told through what you're seeing
[19:46] on screen
[19:47] you can see the file creation you can
[19:50] see
[19:51] the renaming from the old name of
[19:53] apg.exe to the new name
[19:55] of demo.exe and then you can see the
[19:58] rename again
[19:59] from the old name of demo.exe to the new
[20:01] name of demo2.exe
[20:04] pretty neat right and all we did for
[20:06] that as a reminder was we
[20:08] searched for a particular file apg.exe
[20:11] we found its entry number and then we
[20:15] filtered on that entry number getting
[20:17] rid of that previous search in other
[20:18] words
[20:19] show me everything not just apg but
[20:21] everything
[20:22] that has that matching entry number and
[20:25] there we saw
[20:26] all of that evidence so i hope you see
[20:28] how useful
[20:30] these artifacts can be both the mft and
[20:33] the usn journal all right so that wraps
[20:37] up this episode
[20:38] and just to quickly recap what we did
[20:42] we started out by using cape and we used
[20:45] a
[20:45] compound cape target called file system
[20:48] to go after the artifacts in which we
[20:50] were interested
[20:52] specifically the dollar mft in the
[20:55] dollar usn jrnl or even more
[20:58] specifically
[20:59] the alternate data stream dollar j
[21:02] within the
[21:02] dollar usn jrnl so
[21:06] that was pretty easy very easy to obtain
[21:08] that with cape we ended up creating it
[21:10] in
[21:10] a zipped vhdx file we then took that zip
[21:14] file over to our analysis machine
[21:16] unzipped it mounted it pointed mfte cmd
[21:20] at it
[21:20] to generate the two csvs then we popped
[21:23] open those two csvs in timeline explorer
[21:26] and started our analysis and that's
[21:28] pretty much it
[21:30] i hope you found this information useful
[21:32] and as always i'd like to thank you for
[21:34] watching
[21:35] thank you for subscribing and i'll catch
[21:37] you in the next
[21:38] 13 cubed episode
