# CTFlearn: RSA Beginner

Source: https://www.youtube.com/watch?v=20K1ctFzu2Y

English caption extraction; automatic captions may misrecognize commands. Rolling duplicate lines removed.

[00:17] hello world welcome back to another CTF
[00:17] learn challenge video in this video
[00:20] we'll be walking through the
[00:21] cryptography challenge RSA beginner
[00:23] let's get into it I found this scribbled
[00:25] on a piece of paper can you make sense
[00:27] of it and they give us a link to what's
[00:30] on the paper so let's go ahead and look
[00:32] at
[00:39] that and we have the values of EC and n
[00:39] and those are clearly indicative of an
[00:41] RSA Cipher so we're going to copy those
[00:43] and paste them into our solv script over
[00:46] here on the right and we'll go ahead and
[00:48] set those variables
[00:51] up like
[00:53] so and now we need to solve for the
[00:56] cipher text which is C now the first
[00:58] step we need to do is figure out what p
[00:59] and QR now there is a tool called the
[01:01] RSA CF tool that can easily solve this
[01:03] for you but I'm going to show you the
[01:05] manual way so you can get a feel for how
[01:07] RSA is actually solved now no RSA is
[01:10] ever going to be this simple in real
[01:12] life but at least you'll know how the
[01:14] algorithm Works we're going to start
[01:17] with n because that's how we're going to
[01:19] derive p and q n is the modulus and it
[01:21] is equal to P * Q so if we can factor in
[01:25] we get our p and Q now there is an easy
[01:28] way to factor this and we can go to the
[01:31] sage cell server and this is just an
[01:33] online version of sage maath if your
[01:36] modulus gets to a certain length or the
[01:38] number that you want to factor gets to a
[01:40] certain length the website Sage math
[01:42] isn't going to be able to compute it and
[01:43] you'll have to do a local factorization
[01:45] with a local install of sage maath to
[01:47] have access to your host devices
[01:49] hopefully more powerful resources but in
[01:51] this case we can use this site because
[01:53] the N isn't so big that it can't Factor
[01:55] it so we're going to copy in and the
[01:58] function we're going to type in is
[01:59] Factor
[02:00] not in all caps but lowercase Factor
[02:04] open parentheses paste our modulus in
[02:07] there close parentheses and then we're
[02:09] going to click evaluate and it'll take
[02:11] it a few
[02:17] seconds and there we go we have this
[02:17] number times this number and it doesn't
[02:19] matter which one is p and which one is q
[02:22] but these two numbers will be our p and
[02:24] Q values so we'll set P equal to the
[02:29] first value value that we got
[02:36] back and Q equal
[02:36] to the second value we got back all
[02:39] right now we're ready for the next step
[02:42] we need to calculate fi and the way to
[02:45] calculate F or the totient is T
[02:48] =
[02:51] pus1 time q- one like so and you'll see
[02:57] why we need that here in a moment we
[02:59] need t to calculate D and D is going to
[03:02] be the exponent we use to actually
[03:04] decrypt the cipher text so now we need
[03:07] to calculate D and we can do that by
[03:09] doing D equals and we're going to use
[03:10] the pal function and we're going to do
[03:13] the inverse of e which is e to
[03:16] the1 mod T and the third value in the
[03:21] pal function is always modulo so that'll
[03:25] be our D and now we can actually decode
[03:27] the cipher text so we can do
[03:31] print pal C to the
[03:34] D mod in and that's how you get your
[03:37] final flag output so we're going to run
[03:51] this and we get our flag back a decimal
[03:51] version of our flag we actually need to
[03:52] convert this to asky now you can use an
[03:55] online converter but I'm going to show
[03:56] you a way to do it in Python so how we
[03:59] can go about turning this decimal value
[04:02] into asy is we can do DEC for the
[04:05] decrypted plane text equals that and
[04:08] then we're going to say hex DEC like so
[04:12] and if we run
[04:14] that we're going to see that we get a
[04:16] hexadecimal string now we don't want
[04:18] those first two characters so we're
[04:20] going to parse those off by doing this
[04:23] it's a little substring technique that
[04:25] you can do in Python it's called slicing
[04:27] and that's basically just saying from
[04:29] the index of two to the rest of the
[04:31] string slice the portion from the index
[04:34] of two which would be six down here to
[04:36] the end of the string so it's only going
[04:38] to get this part of the string and we
[04:40] can go ahead and show what it looks like
[04:42] when that is the case that way you can
[04:44] just visualize it now we have to convert
[04:46] this heximal string to asky and the way
[04:49] to do that is we're going to do bytes.
[04:52] from hex like so and what this does is
[04:56] it takes our hex string converts it to
[04:58] asking and then converts it to B
[05:00] so you're going to get a B in front of
[05:02] it which is fine nothing wrong with that
[05:03] but we'll throw in an extra little dcode
[05:05] here that way we lose the B and we can
[05:07] just copy and paste the flag as is so
[05:10] now we'll run
[05:12] that and there's our flag RSA is awesome
[05:16] so we'll copy
[05:19] that paste it in and submit all right if
[05:24] you enjoyed the video drop a like And
[05:25] subscribe to the channel to show your
[05:27] support turn on post notifications to
[05:28] get regular in of cyber content directly
[05:31] into your feed check out our patreon
[05:33] join our Discord and follow us on
[05:34] Twitter links in the description box
[05:36] down below and leave any feedback or
[05:38] questions in the comments section down
[05:39] below this is Al mil thanks for watching
[05:42] goodbye world
