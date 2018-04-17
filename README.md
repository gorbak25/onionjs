# Onion JS
Plug&Play Web extension allowing you to use the Tor network from within a modern web browser.

### How?
Web browser Javascript can't create a raw TCP/IP connection with the outside world for security reasons,
because of this implementing an Onion Router in plain JS seems impossible without forwarding tor traffic via XHR/Ajax/WebSocks
to a webserver with full network access. Fortunetly to circumvent censors Tor offers an plug&play obfuscation
layer for network traffic - so called Tor Plugable Transports. One of these transports - meek - obfuscates traffic using
a technique called domain fronting via encapsulating network traffic in a HTTPS connection. I found out that from the context of a web extension plain old javascript is able to communicate
with a meek bridge using only XHR calls and some header rewriting ;)

### Why?
I wanted to write a big project in Javascript & learn the inner workings of Tor and of course Atwood's Law :P

### Right now the implementation is a work in progress - currently the extension is able to connect to the TOR network and fetch the current Consensus.
