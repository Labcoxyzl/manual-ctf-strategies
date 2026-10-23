# MORSE CODE Steganography (2/2) BsidesCT CTF 2018

Source: https://www.youtube.com/watch?v=pJYyyz6HPbQ

English caption extraction; automatic captions may misrecognize commands. Rolling duplicate lines removed.

[00:02] hey YouTube this is a video right up for
[00:02] the challenge odors are like onions from
[00:04] the b-sides Connecticut captial flag
[00:06] competition in this tech Onaga fee
[00:08] category the challenge prompt here is
[00:10] sometimes things on what they seem
[00:12] sometimes things are would they seem
[00:14] damn that's confusing regardless this is
[00:16] a thing so this challenge is brought to
[00:18] you by a friend ordinate SEC DSM and
[00:20] we're giving a download here the hint
[00:21] did not come out until later on in the
[00:23] game and I never solved this during the
[00:26] competition and no one else did in fact
[00:28] the first solve is from just a couple
[00:30] minutes ago like the last hour well I
[00:33] was just trying to get this right and go
[00:35] ahead and submit it now so let's go
[00:37] ahead and dive in we have that MPEG or
[00:39] mp3 files to download sorry and it is
[00:42] simply that it is an audio file we can
[00:44] go ahead and play it I'll use M player
[00:45] and I don't know if you can hear that
[00:47] right now but it's a lot of beeping it's
[00:50] stupid stuff originally I thought oh
[00:52] this is DTMF tones cuz I wasn't really
[00:55] paying attention or listening it's DTMF
[00:57] and then I wanted to go ahead and decode
[01:00] them but for some reason this site is
[01:01] down and I feel horrible about that
[01:04] because I don't know any other resources
[01:05] to decode DTMF tones it's not important
[01:11] because this isn't actually that that's
[01:13] not the correct lead for this if you
[01:15] actually open this up in another utility
[01:16] like sonic visualizer or something to
[01:18] really be able to actually look at the
[01:20] file let's see okay I've got it in
[01:22] download that's good enough this kind of
[01:25] looks like Morse code and maybe that's
[01:30] harder to tell harder to determine but
[01:31] you can see these some waves are long in
[01:34] some ways that are short etc so okay if
[01:36] it's just the same tone beeping over and
[01:38] over again and just varying in lengths
[01:39] maybe this is in fact Morse code so I
[01:42] figured well let's go ahead and play
[01:43] with that let's go ahead and figure that
[01:44] out let's use a Morse code decoder maybe
[01:47] audio file wave so I just went to this
[01:49] site online actually if you do some
[01:51] reconnaissance on the file if you just
[01:52] like where to use EXIF tool I think on
[01:55] that yeah you can see okay it's got a
[01:57] title it's got an artist it's got a band
[01:59] these are specific people that had put
[02:01] this together
[02:02] looks like besides I always reference in
[02:04] here maybe this challenge was originally
[02:05] put there but it says hey this was
[02:07] encoded by this URL and it discusses
[02:10] their their page and also fine let's
[02:12] just jump
[02:13] and use this because that's the correct
[02:15] page that we're on here if we wanted to
[02:16] it says if you've arrived here you might
[02:18] prefer the newer streamlined version
[02:19] which adapts to the speed and frequency
[02:21] of the Morse code over it doesn't give
[02:22] us a whole lot of options and this one
[02:24] does we can actually select something
[02:26] specifically that we want to look at so
[02:27] I'll go ahead and upload a file here
[02:30] I'll put this in the b-sides CTF thing
[02:34] stag ogres are like onions and upload it
[02:38] cool so if we were to play here or move
[02:42] down a little very very bottom it
[02:44] actually gives us the message that it's
[02:46] trying to read out this whole hit do it
[02:49] I'll hit the Go button and it'll slowly
[02:51] process I hope I think I may have to
[02:55] have set like apply or play or something
[02:59] yeah I had I struggled with this one
[03:01] which is why I went to the newer version
[03:03] but this one is this this original page
[03:05] is a lot better for giving us something
[03:07] when you specify to tone and I don't
[03:11] know if you let me do this or not
[03:12] yeah hit the stop button maybe my
[03:16] internet connection is just crap and
[03:18] that's why I can't process this very
[03:19] easily let's try this dream streamlined
[03:22] version I'll upload this guy hit play
[03:26] and okay audio is on trying to process
[03:30] some of this stuff let me turn that down
[03:36] and we get this text that's coming out
[03:39] of it the other message is that you
[03:40] actually be able to receive from this if
[03:42] you looked at it with two-tone or with
[03:44] other things it says this is like 20 wpm
[03:48] with a higher frequency etc I'm in at
[03:51] the very end it looks like it's getting
[03:53] us bTW
[04:00] yeah bTW and what does a I don't forget
[04:00] the proper terminology it was in fro
[04:02] sign or something Morse code yeah yeah
[04:10] Pro signs for Morse code yeah so BTW is
[04:13] like starting a new new thing
[04:25] I don't want to say like paragraph or
[04:25] break through but okay break yeah break
[04:28] so what I looked at that I realize okay
[04:32] same as character equal signs or
[04:33] something and I thought that's peculiar
[04:34] because when I look at this clearly this
[04:37] this is hard to determine its base64 but
[04:39] I know it may vary will be another base
[04:41] like a lot of column cop capital letters
[04:44] is like base 32 so I didn't process
[04:47] immediately that the BT or the the
[04:49] breaks were referring to equal signs but
[04:51] when I look at it later on it makes so
[04:53] much more sense to me so I didn't see
[04:57] the hint originally at the time as well
[04:58] it wasn't out at that point but had I
[05:01] seen it earlier I might have had a
[05:02] better luck with this because that is in
[05:04] fact something that made look like base
[05:06] 32 so let's go ahead and import base 64
[05:10] in Python base 64 and Python that module
[05:13] does in fact have a be 32 in code and
[05:16] decode set of functions so we can base
[05:18] 32 decode i'll give it this and maybe i
[05:21] had wrong padding there yep okay so
[05:23] throw another equal sign on there you
[05:24] can see it's trying to try to throw
[05:25] something else in there and we're given
[05:27] this right interesting
[05:30] peculiar i have no idea what this is I
[05:32] have literally no idea what this is I
[05:33] thought it was base 85 or the 58 stuff
[05:36] and then eventually looking at the hint
[05:38] once it got released it says oh not all
[05:41] your not all your base are 64 and I
[05:44] agreed with this that this made sense in
[05:47] my mind from what we had already figured
[05:48] out okay Suman assumingly base 32 and I
[05:52] screwed around with like oh add more
[05:53] equal signs subtract equal signs just
[05:56] twink mudge and and fudge some of the
[05:58] characters in here but I was given this
[06:01] at the end of day didn't know what to do
[06:03] with it had no idea what it was kept
[06:04] trying to play with it blah blah blah
[06:06] the competition ended everything was
[06:08] over and I figured we asked the guys
[06:10] what is this thing and they tell these
[06:12] oh it's Rob 47 and like what is that not
[06:16] like base 37 or anything base 47 I found
[06:21] it and read a little about it and it's a
[06:22] it's peculiar because how do you looked
[06:24] at like literally the rot13 like a
[06:26] regular Caesar cipher thing on Wikipedia
[06:28] they actually talk about rod 47 and the
[06:30] variation ii it says oh it's a
[06:32] derivative of rot13 where it
[06:34] is scrambling the basic letters it also
[06:36] treats numbers and common symbols as
[06:38] part of the translation series instead
[06:40] of using just a to z alphabet it uses
[06:42] all the characters like everything in
[06:44] ASCII so you can get some interesting
[06:46] craft very cool right I'd never heard of
[06:49] this a night and I definitely want to
[06:51] add this to like my CTF katana thing if
[06:53] you haven't seen that that's a cool
[06:54] thing go ahead and check out John
[06:56] Hammond github CTF katana has a lot of
[06:58] references and resources for our CTF
[07:00] stuff I definitely do add this into it
[07:02] because I just thought it was very very
[07:03] cool if you just go ahead and go to a
[07:05] rot 47 decoder track one down online
[07:08] build something interesting stuff we can
[07:11] go ahead and submit this pace it in idle
[07:15] where'd you go is it all gone did I lose
[07:18] it all gosh dang it
[07:19] alright let's read let's redo that I may
[07:22] have closed out of it like a fool I
[07:32] don't even have the whole thing to copy
[07:32] and paste in for equal signs what I use
[07:37] 60 for my bed 32 there we go cool let's
[07:43] go ahead and throw this into raw 47
[07:45] decrypt it it says from SEC DSM with
[07:49] love that is the flag that is what we
[07:52] should submit and that is what would
[07:54] give us 500 points except none of us got
[07:57] it during the competition no one that
[07:59] was playing figured this out but after
[08:01] having that conversation with the
[08:02] creator's afterwards we realized it was
[08:04] rod 47 very cool I'd never heard of that
[08:07] before so hey maybe that's a nugget for
[08:09] you too hope you guys enjoyed this thank
[08:11] you guys for watching and before I go I
[08:14] want to give a quick shout out to the
[08:15] people that support me on patreon so
[08:17] thank you guys so much $1 a month or
[08:19] more on patreon will give you a special
[08:20] shout-out just like this at the end of
[08:22] every video you got your name added to
[08:23] the list get your name up in lights it's
[08:25] just a feel-good feeling it feels like
[08:27] you're helping people in the world
[08:28] helping some guy just trying to make his
[08:29] own path it's cool five dollars or more
[08:34] on patreon will give you early access to
[08:35] everything that are at least on YouTube
[08:36] before it goes live so I like to record
[08:38] some videos in bulk but I'm going on a
[08:40] street feeling good actually being
[08:41] productive for once and I will let them
[08:44] sit in a shared Google Drive so that
[08:47] anyone can access them
[08:48] while I'm waiting on YouTube to
[08:50] gradually release them on a schedule so
[08:52] slowly but surely if you want the
[08:54] content right when it's ready right when
[08:56] it's hot right when I've got stuff
[08:57] recorded that's the way to do it and it
[08:58] helps me out I'm grateful and I thank
[09:00] you for your help and support if you did
[09:03] like this video please do like comment
[09:05] and subscribe join our discord server
[09:06] link in the description it is a cool
[09:08] community full of CTF players
[09:09] programmers and hackers it's slowing
[09:11] down we got a lot of people in there and
[09:12] hopefully the the life will come out of
[09:14] it again but we'll jump in the next CTF
[09:17] right I think square CTF is coming up
[09:18] this this weekend I'll be besides
[09:20] Delaware give another talk playing pros
[09:22] versus Joe's again
[09:23] cool cool stuff so All Right see you
[09:26] guys another video I love you I'll talk
[09:28] to you later
