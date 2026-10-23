# How to resend individual requests with Burp Repeater

Source: https://www.youtube.com/watch?v=_Wifm2g9ugg

English caption extraction; automatic captions may misrecognize commands. Rolling duplicate lines removed.

[00:08] in this tutorial
[00:08] we'll cover how to resend individual
[00:10] http requests
[00:12] using burp repeater and we'll look at
[00:14] various related workflows
[00:16] and options that you can use to support
[00:18] your testing
[00:24] burp suite repeater is the tool that you
[00:24] can use
[00:25] to resend individual requests modify
[00:28] them
[00:29] and issue them over and over
[00:32] the easiest way to use burp repeater is
[00:35] to send requests to it
[00:37] from other tools in burp so burp suite
[00:40] you can send requests between
[00:42] burp tools anywhere that you see them
[00:48] so i'm going to launch burp's embedded
[00:48] browser
[00:50] and visit a website
[00:56] the request is intercepted in proxy so
[00:56] we can use the context menu
[00:58] and select center repeater from here
[01:01] or if we prefer we can go
[01:04] to the http history we click on any
[01:07] request that we're interested in again
[01:09] use the context menu
[01:10] select center repeater or we can go
[01:13] to the target tab and
[01:17] select an item that we're interested in
[01:19] and do
[01:20] send to repeater from the context menu
[01:22] again or from any
[01:23] individual request panel we can do the
[01:26] same
[01:28] so if we send a request to repeater
[01:30] there it appears
[01:32] on the left hand side in the request
[01:33] panel we can see the request
[01:35] and we can also edit it we can click
[01:38] send
[01:39] to issue the request and then on the
[01:41] right hand side in the response panel
[01:43] we can see the response that came back
[01:45] from the server
[01:47] if we want we can send the request over
[01:50] and over
[01:51] we can edit it and send it again
[01:55] change it again we can try different
[01:59] things
[01:59] get different status codes back
[02:01] different responses
[02:03] next to the send and cancel button we
[02:05] have these
[02:06] back and forwards buttons where we can
[02:08] walk through the history
[02:10] of requests that we've made and see each
[02:12] request and response
[02:14] and on each button there's a little drop
[02:15] down where we can jump straight to an
[02:17] item
[02:17] in our history if we want to send that
[02:20] request again
[02:22] but repeater can also handle redirects
[02:25] so if we find a request that caused a
[02:28] redirection response
[02:30] and send that to repeater
[02:37] here we can see the server replied with
[02:37] 301 status code which is a redirection
[02:40] and we now have this follow redirection
[02:42] button if we click that
[02:44] but we'll update the request on the left
[02:47] to be the redirected request
[02:49] and it will show the response from that
[02:51] on the right
[02:57] if we want we can do this automatically
[02:57] so if we go to the repeater menu
[02:59] we have these options for follow
[03:00] redirections if we turn those on
[03:04] we hit send this time but automatically
[03:08] follow the redirect and we see the final
[03:10] response on the right
[03:12] and down at the bottom in the status bar
[03:14] that tells us that it followed
[03:16] one redirection there are some other
[03:19] handy options
[03:20] on the repeater menu so by default
[03:23] but repeater will update the content
[03:25] length as you edit requests if you
[03:27] prefer you can turn that off
[03:29] by default but we'll unpack gzip and
[03:32] deflate content
[03:33] in responses if you prefer you can turn
[03:35] that off
[03:37] you can tell about whether to process
[03:39] cookies
[03:40] in redirects you can change the
[03:43] view of repeater so you can have
[03:46] top bottom split or other views if you
[03:49] prefer
[03:55] you can use hotkeys to send items to
[03:55] burp
[03:56] repeater so we select an item and type
[03:59] control
[03:59] r or command r on mac
[04:04] that request comes into repeater we can
[04:07] also use control space or command space
[04:09] to issue the request you can configure
[04:12] burps hotkeys by going to user options
[04:16] misc and editing the configured hotkeys
[04:19] here
[04:24] if you send multiple requests to
[04:24] repeater
[04:26] each one will create a different tab
[04:30] in repeater where you can work so each
[04:33] tab has its own request and response
[04:35] panels it has its own history
[04:37] so you can work independently on
[04:38] different requests this is really handy
[04:40] in your testing workflow
[04:42] if you are testing different endpoints
[04:44] of the application different features
[04:46] and you want to play with one request
[04:47] for a bit
[04:48] switch and work on something else you
[04:50] can then keep your work and easily
[04:52] switch back
[04:54] if you want you could rename tabs by
[04:56] clicking on the tab header
[04:58] and typing in a different name for the
[05:00] tab
[05:01] this lets you easily label your tabs so
[05:03] you can come back to them and remember
[05:05] where you left off
[05:06] you could reorder tabs by dragging them
[05:09] in the tab header
[05:12] if you're finished with the tab you can
[05:13] close it by clicking on
[05:15] the little x there's one more way
[05:19] to start off with both repeater and that
[05:21] is you can click on these little three
[05:23] dots
[05:24] to create a new tab and here we're going
[05:26] to say
[05:27] type http because we're working on http
[05:29] requests
[05:30] if we were working on websockets we
[05:32] would select that option and it would
[05:33] create a different ui
[05:35] for working on websockets messages we'll
[05:37] cover websockets testing
[05:38] in a different tutorial so we click on
[05:41] http
[05:43] we get a new empty tab with no request
[05:45] or response
[05:46] no target details specified so we could
[05:48] configure all of these manually
[05:50] but there's another nice little feature
[05:52] in burp if you have a url
[05:54] that you're interested in if you copy
[05:57] that to the clipboard
[05:59] you can then select paste url as request
[06:02] that will then create a request and
[06:05] configure the target details
[06:06] from that url and you can then send it
[06:10] so that's how to resend individual http
[06:14] requests with birt repeater
[06:15] and various related workflows and
[06:18] options
