# Cryptography   Lab 5   Cooking with the Cyberchef

Source: https://www.youtube.com/watch?v=UtqmiI7k9lU

English caption extraction; automatic captions may misrecognize commands. Rolling duplicate lines removed.

[00:08] cyberchef is a web-based tool that
[00:08] allows cyber Security Professionals to
[00:10] quickly and easily analyze decode and
[00:13] transform data in various formats and
[00:16] these are formats like base 64 AES gzip
[00:20] exor AES binary and so much more and
[00:24] really what's so good about cyberchef is
[00:26] that allows you to do this in a
[00:28] step-by-step recipe format where you can
[00:30] see all of it in real time no operating
[00:33] system tools required so there's only
[00:35] one thing left for us to do let's cook
[00:39] inside of your cryptography folder
[00:40] you'll find an OB fiscated code.txt
[00:44] file and we'll come back to that a
[00:46] little bit later in the lab but just
[00:47] keep it handy in the meantime go and
[00:49] open up a browser go to google.com and
[00:52] then make a search for cyers
[00:59] chef and then we should see a GitHub
[00:59] link let's go ahead and click on that
[01:00] one right there cyberchef was actually
[01:03] developed by the gchq or government
[01:06] Communications Headquarters of the
[01:07] United Kingdom and this is their GitHub
[01:10] repository and with it we have a live
[01:12] demo that we can use select that demo
[01:15] link when you're ready now the interface
[01:18] for cyberchef is honestly really
[01:20] intuitive you have these operations on
[01:22] the left hand Pane and you can do
[01:24] various things like encode decode
[01:26] encrypt decrypt and so on and so you
[01:29] drag these operations into the middle
[01:31] column to eventually build your recipe
[01:33] that achieves each of the operations in
[01:35] a step-by-step manner so let's get some
[01:38] input inside of the top right and let's
[01:39] put in let's cook now what we need to do
[01:42] next is see if we can maybe reverse that
[01:45] as an example if we type in Reverse
[01:47] under the operations we can drag that
[01:49] operation into our recipe and look at
[01:52] the bottom right right away you can see
[01:54] it immediately reverses our input that's
[01:56] pretty cool now maybe we want to base 64
[01:59] or encode it so we can type 2 base 64
[02:03] drag that onto the recipe and now we
[02:05] have a reversed input that is also base
[02:07] 64 encoded after it's been
[02:10] reversed and it doesn't have to stop
[02:12] there we can keep on going we can maybe
[02:14] even convert this to octl now so now we
[02:16] get that series of digits that almost
[02:18] looks like what we see inside of IP
[02:20] addresses and it also works both ways so
[02:23] let's go and copy that output that we
[02:25] have after three operations of this
[02:27] recipe with some encoding and
[02:28] obfuscation and now let's clear the
[02:30] recipe and then paste that inside of the
[02:34] input now let's see if we can reverse it
[02:37] so instead of doing the step by step
[02:39] cyberchef actually has some intelligence
[02:41] to it notice that little wand it says
[02:44] from octal from Bas 64 well I'm going to
[02:47] go and click on that and as I do you can
[02:50] see it actually populates the recipe to
[02:52] some degree for us and that's because
[02:54] cyberchef has a little bit of
[02:56] intelligence to it where it can perform
[02:58] some level of analysis
[03:00] based on what you've provided it and
[03:02] make its best guess at what levels of
[03:05] encryption or encoding or officiation
[03:07] might be in place and then it'll try to
[03:09] populate the recipe for you to save you
[03:11] some time and what's funny is the
[03:13] easiest one of just reverse text it
[03:15] couldn't guess that but it could guess
[03:17] Bas 64 and octal so let's go and put
[03:20] that reverse step back in and bring it
[03:22] back to its original state all right
[03:24] let's do something a little bit more
[03:26] challenging now remember that OB
[03:28] fiscated code well let's go back to that
[03:30] text file let's select all of it and
[03:33] let's bring it inside of the input
[03:35] section of cyberchef and then start
[03:37] working on it
[03:38] together cool okay so this must be base
[03:42] 64 right we see those two equal signs
[03:44] over there worth of padding let's go and
[03:47] grab a from base 64 operation and drag
[03:49] it in the
[03:55] recipe and that didn't
[03:55] work so that's kind of interesting and
[03:58] now we're seeing something that looks
[04:00] like it should be base 64 but it's not
[04:03] working so let's try something out here
[04:06] notice that if we highlight the
[04:08] selection of text over in the input
[04:11] column it also reflects what we see in
[04:13] the output column they're sort of tied
[04:15] together but if we highlight all of it
[04:18] there's something off it's not
[04:21] registering those two equal signs
[04:25] they're not being accounted for in the
[04:27] output those two equal signs suggest
[04:29] that there's padding they're not
[04:31] actually
[04:32] characters so we do have base 64 here
[04:35] but something's not right however
[04:38] something sort of stands out from the
[04:40] input and the output after a base 64
[04:42] operation it looks like there's series
[04:45] of characters even though they're not
[04:47] legible they look the same it looks like
[04:50] they were moved or changed in an order
[04:53] of
[04:54] operation and so typically when you see
[04:56] multiple series of characters moved in
[04:59] the same way that makes me think
[05:01] rotation so possibly rth 13 so let's go
[05:05] and put a rth 13 operation before the
[05:07] base 64 and see what
[05:10] happens it looks like something happened
[05:12] but we're still not sure we can check
[05:14] with that little magic wand and we can
[05:15] see it's saying gunzip so it's actually
[05:18] suggesting that there's a zip action
[05:20] here as well too let's run gunzip or
[05:23] gunzip and there we go so it actually
[05:26] did work it actually did pick it up
[05:28] correctly thank you cyberu
[05:30] and well this is clearly binary so let's
[05:33] do a binary and run a from binary
[05:36] operation awesome so this looks kind of
[05:40] interesting once again we're seeing a
[05:43] lot of repetition of characters however
[05:46] there is a sneaky equal sign at the end
[05:48] which could suggest base 64 so let's try
[05:51] out another base 64 operation and
[06:01] see aha okay so that's why we have hex
[06:01] output that's why those characters
[06:03] looked so weird so we can do a from hex
[06:05] at this
[06:06] point there it is that's the original
[06:09] code and that definitely looks
[06:12] suspicious to me I mean it's actually
[06:14] calling out to an evil code one and also
[06:17] trying to invoke mimik cats and dump
[06:20] creds and that's some crafty malicious
[06:23] Powershell code right
[06:25] there so it's pretty amazing right how
[06:28] many layers that things can be OB
[06:30] fiscated and encoded but a tool like
[06:32] cybers chea really allows us to work
[06:34] through the process in real time and at
[06:36] a comfortable Pace where we can stop
[06:39] pause analyze and think about our next
[06:41] step again without any tools and it
[06:44] doesn't have to be about anything
[06:46] malicious you could just be using this
[06:48] to encode a bit of a secret message to
[06:50] send to a friend or maybe you could be
[06:52] trying to see how your input data looks
[06:55] like after several layers of encoding to
[06:57] be passed through some type of web app
[06:59] application and maybe over to a database
[07:03] so all in all there's a lot of use cases
[07:05] it's really handy and this is just the
[07:07] tip of the iceberg with cyberchef you're
[07:09] definitely going to be using this tool
[07:11] when you're in the cyber security
