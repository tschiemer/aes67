# aes67
Framework for AES67 targeting embedded devices.

WORK IN PROGRESS

Designed in particular to be employed on embedded devices and thus not relying on dynamic memory allocation (although optionally possible where meaningful), tight control over memory usage, no dependencies on external libraries, in particular as few hardware/library abstractions are used as possible - the framework will have to be adapted according to needs.

Components are intended to be as minimal as possible to allow for essential AES67 operations and be as interoperable as possible - in detail this is not yet clear and requires further investigation into different manufacturer-dependent implementations.



https://github.com/tschiemer/aes67

## Rough feature/support roadmap

- Clock / Synchronisation
  - [ ] PTPv2 / IEEE1588-2008 (as per AES67-2018)
  - [ ] PTPv1 / IEEE1588-2002 ?
  - [ ] PTPv2.1 / IEEE1588-2019 ?
  - [ ] IEEE802.1AS-2011 ?
  

- Discovery & | Management
  - [x] SAP (required for broader interoperability)
    - [x] ~~zlib (de-)compression support?~~ -> interface for external implementation
    - [x] ~~authentication support?~~ -> interface for external implementation
  - [x] SDP
  - [ ] SIP ? (for unicast management according to standard, but most systems use multicast only..)
  - [ ] RSTP ? (meaningful for system with Ravenna-based components if no RAV2SAP)
  - [ ] [AES70/OCA](https://github.com/tschiemer/ocac) *work in progress*
    - [x] [mDNS / DNS-SD](https://github.com/tschiemer/minimr)


- Stream
  - [ ] RTP/RTCP

  
- Command line / developer utilities
  - SAP
    - [x] sap-pack, sap-unpack
    - [ ] ~~sap-server~~ -> general session server
    - [ ] RAV2SAP alternative? (discovery through mDNS, querying through RTSP)
  - SDP
    - [ ] sdp-parse 
  - PTP
    - [ ] ptp-monitor? -> https://www.ptptrackhound.com/
    - [ ] ptp-server?



## In a Nutshell

Aspects of AES67 and the implementation considerations within this framework.

*Disclaimer: my understanding as someone learning about AES67 still might not be error free, please drop me a line if you see something wrong.*

### Clock / Synchronisation

AES67 devices are ment to synchronize their local clocks through PTPv2 (IEEE 1588-2008) which foresees
a *best* (grand-)master clock telling all slaved devices the current time.  
This local clock will slightly drift with respect to the grandmaster clock and thus the local clock
is to adapt its effective (network) clock rate to match the grandmaster clock as good as possible.

This local (network) clock then is ment to drive the stream's media clock and implicitly any
other audo processing components, in particular also ADCs and DACs thus achieving a tight synchronisation
very much like a classical wordclock (WC).

If multiple clock synchronization sources are given, say a network clock and a wordclock, the wordclock will
likely be more precise as there should not be any variability due to network conditions - the device would be
a rather good candidate to act as grandmaster clock and generally the WC should be preferred if the clock source
is identical (the principle of a strictly hierarchical clock distribution with but one overall clock master
and transitive master-slave relationships only should be respected, obviously).

Is a clock or synchronization required for any type of device? Pragmatically speaking, no.
A passive device - such as a recorder-only device - doesn't necessarily have to be synchronised
to a clock. Assuming all senders are properly synchronised then a recorder may just
listen to all stream packets and store them after (optimally) aligning them in time.

Optimally (realtime) playout should occur after time alignment (if multiple sources are given).
Pragmatically speaking, time alignment isn't necessary and would allow for simpler implementations,
but in this case audio sent at the same time would be played back at (slightly) different times
which might be unwanted behaviour and - strictly speaking - somewhat beats the purpose of tight
synchronisation.

What's this with *time alignment*? Well, streams can be configured with different packet
`ptime`s (realtime duration of stream data in a packet) which implies different sizes of receive
buffers which implies different playout times. So, allowing different combinations of incoming 
stream configurations (w.r.t. ptime) makes implementations more complicated, because the lower
latency streams (smaller `ptime`) will have to adapt to the highest latency stream (`maxptime`,
so to speak). And technically speaking, receive buffer changes (due to combining of different
ptimes) can't happen without dropping or inserting samples - which leads to the decision of
either not aligning received streams w.r.t. time or a priori fixing a common max delay setting.

Non-dedicated devices - such as computers with virtual sound cards - would seem to be an
interesting case to be considered w.r.t. the clock/synchronisation.

### Discovery & Management

Discovery and management approaches are generally not needed - but require other (ie manual) configuration. For ease of integration such methods are generally recommended and thus considered within this framework.

Joining of multicast session_data essentially requires but the joining of respective multicast group.
Setting up a unicast session_data requires cooperation of the partners, ie some form of control protocol.
Seemingly unicast sessions are barely in use (see [wikipedia](https://en.wikipedia.org/wiki/AES67#Adoption)).


AES67 generally leaves the choice of discovery and management mechanism open, but it names several possibilities to be aware of:

 - Bonjours / mDNS (DNS-SD) is proposed in conjunction with SIP, ie the device's SIP URI / service is announced (unicast sessions)
 - SAP is proposed for announcement of *multicast* sessions
 - Axia Discovery Protocol
 - Wheatstone WheatnetIP Discovery Protocol
 - [AMWA NMOS Discovery and Registration Specification (IS-04)]( https://github.com/AMWA-TV/nmos-discovery-registration)

Not mentioned, but seemingly also used in distributed products (according to [wikipedia](https://en.wikipedia.org/wiki/AES67#Adoption)):

- Real-Time Streaming Protocol

As discussed elsewhere AES70 - a rather young discovery and control standard of networked audio devices - is suggested as a promising solution.

*Conclusion*

For broad integration SAP seems like a general requirement for any device.

Further it is (generally) proposed to use AES70 for discovery and management, in particular because the standard is a collaborative effort and provides several meaningful features out of the box (although it is somewhat complex) beyond discovery and stream management.

SIP may be considered (in the future) for management of unicast streams but it is not only barely adopted, as an (somewhat elaborate) additional service it only provides connection management.

RTSP may be considered (in the future) for management of unicast streams aswell as service discovery of Ravenna streams.

### Audio

#### Encoding

AES67 Audio is to be streamed in L16 or L24 encoding; that is, each sample is a two-, three-byte respectively signed integer
in two's complement representation in network byte order (bigendian),
 samples are interleaved.
The common I2S & TDM inter-chip audio protocols, AES3, AES10 (MADI), AES50  use identical formats (roughly speaking).
Thus, other formats are generally not considered herein.

#### Routing

Given a fixed local audio sour multicast streaming is rather straightforward.

For potential optimization multiple instances might be considered supported.

In the most simple case incoming streams might be handled similarly, ie just one
multicast stream might be listened to and passed on to the local output.

But if audio is to come from different sources the situation gets more complicated: either
the device has the capability of listening to multiple streams and extracting the necessary
channels or the single channels are joined on another device into a single (multicast) stream.
Obviously this would introduce further latency and make configuration more complicated.

Interesting to note, even basic AES70 connection management by default 
allows for internal routing of local channels to transmitted stream channels (of a multichannel 
stream), and analogously allows for custom assignment of incoming stream channels to
local output channels. Thus a receiving device should support (at most) as many streams as it
has internal (receiving) channels - although practically speaking there typically will be less
senders than relevant received channels unless each sender transmits only one relevant channel,
so this can be constrained (thereby constraining possible system configurations).

In the sense of AES70 transmission and reception buffers are designed to provide a single
interface for local in- and output of channels to be processed but allowing for merging of
multiple stream sources into one reception buffer (discarding any unwanted audio channels).




## Corny details

### SAP

- Does not support encryption.
- Provides interfaces for zlib de-/compression. For the moment being it is assumed that compression is not used by implementations.
- Provides interfaces for authentication.
- Can be used as an abstract service with basic session memory (only identifiers, ie no payloads, saved) and timeout detection but can also used to parse or generate SAP messages in a standalone fashion.

### SDP

- Narrowed down to options and attributes as required for AES67 streams.-
- Supports relevant session- and/or media-level options (connection, ref-clock, recvonly|sendonly|inactive|sendrecv).
- Supports multiple ptp reference clocks on both session-/media level (1588-2002/08/19, 802.1AS-2011)
- Support for audio media with dynamic payload types *only* and L8/L16/L24/L32 encoding media encoding.
- Intended to support encoding and ptime negotiation - capabilities are discarded (fallback to non-negotiated configuration) if capabilities other than ptime related are offered.
- Parser to/generator from internal struct.
- Provides implementable interface for unhandled media, options and attributes.
  - Media sections if non-audio and unrecognized *predefined* payload types.
  - Unknown dynamic payload type encodings.

## Utilities

Primarily test/developer utilities that allow for convenient testing (or simple interactions) - socat is your friend. 

### `sap-pack`
```
Usage: ./sap-pack (announce|delete) <msg-hash> <origin-ip> [<payloadtype>] <sdp-file>
Writes SAPv2 packet to STDOUT.
Examples:
./sap-pack announce 123 10.0.0.2 test.sdp | socat -u - UDP4-DATAGRAM:224.2.127.254:9875
watch -t 300 "./sap-pack announce 123 10.0.0.2 test.sdp | socat -u -v - UDP4-DATAGRAM:224.2.127.254:9875"
```
### `sap-unpack`
```
Usage: ./sap-unpack [-h?ad]
Attempts to parse SAP packets incoming on STDIN and prints to STDOUT in the following format:
	 (announce|delete) <hash> <ip> <payload-type>
	 <payload-data>
	 <newline>
Options:
	 -a	 Print SAP headers
	 -d	 Print basic dbg info to STDERR
	 -h,-?	 Prints this help.
Examples:
socat -u UDP4-RECVFROM:9875,ip-add-membership=224.2.127.254:192.168.1.122,fork - | ./sap-unpack -a
```

### `sdp-parse`

```
Usage: ./sdp-parse [-hd]
Attempts to parse SDP incoming on STDIN (primarily useful to validate custom SDP files quickly).
Options:
	 -h	 Prints this info
	 -d	 Prints some debug info to STDERR
```

## References

- [AES67-2018 Standard document](https://www.aes.org/publications/standards/search.cfm?docID=96)
- [IEEE1558-2019 (PTPv2.1) Standard document](https://standards.ieee.org/content/ieee-standards/en/standard/1588-2019.html)
- https://en.wikipedia.org/wiki/AES67
- https://hartung.io/2020/07/aes67-resources/ (nice collection of resources)

## License

Copyright (C) 2021  Philip Tschiemer

GNU Affero General Public License v3
