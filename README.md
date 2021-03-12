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
  - [ ] RTSP ? (meaningful for system with Ravenna-based components if no RAV2SAP)
  - [ ] [AES70/OCA](https://github.com/tschiemer/ocac) *work in progress*
    - [x] [mDNS / DNS-SD](https://github.com/tschiemer/minimr)


- Stream
  - [ ] RTP/RTCP

  
- Command line / developer utilities
  - SAP
    - [x] [sap-pack](#sap-pack): create SAP message(s)
    - [x] [sap-unpack](#sap-unpack): parse SAP message(s) 
    - [ ] [sapd](#sapd): SAP daemon (with Ravenna support)
  - SDP
    - [x] [sdp-parse](#sdp-parse): parse SDP(s)
    - [x] [sdp-gen](#sdp-gen): generate SDP
  - RTSP/HTTP
    - [x] [rtsp-describe](#rtsp-describe): retrieve SDP from RTSP service
    - [ ] rtsp/http combo server?
  - RAVENNA
    - [ ] ~~RAV2SAP~~ -> [sapd](#sapd)
    - [x] [rav-lookup](#rav-lookup): browse for RAVENNA sessions/devices
  - PTP
    - [ ] ptp-monitor? -> https://www.ptptrackhound.com/
    - [ ] ptp-server?
  - RTP/RTCP
    - [ ] rtp-send: send RTP (from STDIN)
    - [ ] rtp-recv: receive RTP (to STDOUT)
  - Support
    - mDNS (abstraction for service *discovery*)
      - [ ] dns-sd
         - [x] discovery
         - [ ] registration (?)
      - [ ] ahavi



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
The common I2S & TDM inter-chip audio protocols  use identical formats (roughly speaking) which shall be the primary encoding focused herein.
AES3, AES10 (MADI), AES50 are frame-based and use or can use a least-significant-bit to most-significant-bit encoding.

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
- Note: global multicast scope (224.2.127.254) vs highest address in administered scope (AES67 devices typically use **239.255.255.255**). 
  
### SDP

- Parser to/generator from internal struct.
- Narrowed down to options and attributes as required for AES67 streams.
- Supports relevant session- and/or media-level options (connection, ref-clock, recvonly|sendonly|inactive|sendrecv).
- Supports multiple ptp reference clocks on both session-/media level (1588-2002/08/19, 802.1AS-2011)
- Support for audio media with dynamic payload types *only* and L8/L16/L24/L32/AM824 (AES3) encoding media encoding.
- Intended to support encoding and ptime negotiation - capabilities are discarded (fallback to non-negotiated configuration) if capabilities other than ptime related are offered.
- Provides implementable interface for unhandled media, options and attributes.
  - Media sections if non-audio and unrecognized *predefined* payload types.
  - Unknown dynamic payload type encodings.
- Provides implementable interface for adding custom session- or media-level attributes.

## Utilities

Primarily test/developer utilities that allow for convenient testing (or simple interactions) - socat is your friend. 

### `sap-pack`
```
Usage: ./sap-pack [-h|-?] | [-a|-d] [--hash <hash>] [-o <origin-ip>] [-p <payloadtype> | --v1] [<file> ...]
Writes SAP packet to STDOUT.
If a <file> is given assumes it is a single payload file.
If no <file> is given tries to read from STDIN (if SDP payload is assumed looks for SDP start, ie "v=0").
Options:
	 -h,-?		 Prints this info.
	 -a		 Announcement type message (default)
	 -d		 Delete type message (note: expects but an originator line)
	 --hash <hash>	 Force this hash id (if not given tries to extract from SDP file, session id)
	 -o <origin-ip>	 Force this originating IP (if not given tries to extract from SDP file, originating addr)
	 -p <payloadtype>	 Use this particular (MIME) payload type (if not given uses 'application/sdp')
	 --v1		 Use a SAPv1 packet format (implies SDP payload, allows a zero-hash, requires IPv4 origin)
	 --xf		 Attempt to parse SDP payload, on fail fallback to given hash and origin-ip
	 -v		 Print some basic info to STDERR
Examples:
./sap-pack test.sdp | socat -u - UDP4-DATAGRAM:239.255.255.255:9875
watch -t 300 "./sap-pack  test.sdp | socat -u -v - UDP4-DATAGRAM:224.2.127.254:9875"
```
Note that you can improvise a SAP server that just broadcasts SDPs regularly :)

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
socat -u UDP4-RECVFROM:9875,ip-add-membership=239.255.255.255:192.168.1.122,reuseport,reuseaddr,fork - | ./sap-unpack -a
```

### `sapd`
```
Usage: ./sapd [-h|-?] | [-d] [-p <port>] [--l <mcast-scope>] [--s <mcast-scope>] [--ipv6-if <ifname>] ..
Starts an (SDP-only) SAP server that maintains incoming SDPs, informs about updates and keeps announcing
specified SDPs on network.
Communicates through local port (/var/run/sapd.sock)
Logs to syslog (identity sapd)

Options:
	 -h,-?		 Prints this info.
	 -d,--daemonize	 Daemonize
	 -v		 Also print syslog to STDERR
	 -p,--port <port>	 Listen on this port (default 9875)
	 --l<mcast-scope>, --s<mcast-scope>
			 Listens, sends respectively on these IPv4/6 multicast scopes (multiple possible). Scopes:
				 4g	 IPv4 SAP global (224.2.127.254)
				 4a	 IPv4 SAP administered (239.255.255.255)
				 6ll	 IPv6 SAP link local (FF02::2:7FFE)
				 6ip4	 IPv6 SAP ip4 scope local (FF03::2:7FFE)
				 6al	 IPv6 SAP admin local (FF04::2:7FFE)
				 6sl	 IPv6 SAP site local (FF05::2:7FFE)
			 Default listen: 4g + 4a + 6ll
			 Default send: 4a
	 --ipv6-if	 IPv6 interface to listen on (default interface can fail)
	 --rav		 Enable Ravenna session lookups
	 --rav-no-autopub
			 Disable automatic publishing of discovered ravenna sessions
	 --rav-pub-delay <delay-sec>
			 Wait for this many seconds before publishing discovered ravenna sessions
			 through SAP (0 .. 360, default 5)
	 --rav-upd-interval <interval-sec>
			 Wait for this many seconds checking for SDP change of already published
			 ravenna device (0 .. 360, default 0)
	 --rav-no-handover
			 Discovered ravenna session that are also found through SAP will give NOT
			 up local management (assuming another source, possibly the originating device)
			 will actually handle this).
Compile time options:
	 AES67_SAP_MIN_INTERVAL_SEC 	 30 	 // +- announce time, depends on SAP traffic
	 AES67_SAP_MIN_TIMEOUT_SEC 	 600
	 AES67_SAPD_WITH_RAV 		 1 	 // Ravenna sessions supported?

Examples:
sudo ./sapd -v --ipv6-if en7 & socat - UNIX-CONNECT:/var/run/sapd.sock,keepalive
```
A SAP daemon with a local client interface that supports local registration of sessions
aswell as lookup and injection of ravenna based sessions - somewhat like [RAV2SAP](https://www.ravenna-network.com/aes67/rav2sap/).

*yet requires field testing (feel free)*

Essentially any connection to the AF_LOCAL socket is considered a subscription and will receive updates but allows also
for registration and deletion of locally managed sessions (SDP files).

For documentation of protocol/interface used through AF_LOCAL sockets, see [src/include/aes67/utils/sapd.h](src/include/aes67/utils/sapd.h).

(note: AES67-2018 is specified for IPv4 primarily, consider IPv6 a proof of concept and for other purposes..)

---

The original [RAV2SAP](https://www.ravenna-network.com/aes67/rav2sap/) essentially is intended to translate RAVENNA-style mDNS-based
discovery into SAP-based discovery (but also allowing for a managed point of manual SDP management).

It is somewhat straightforward as in:

1. listen to mDNS services
2. get SDP of discovered streams
3. and pass to SAP

To improvise something to the same effect without the use of `sapd` you can also make use of utilities given herein:

```bash 
rav-lookup -v | rtsp-describe -v | sap-pack -v | socat -u - UDP4-DATAGRAM:224.2.127.254:9875
```

Note: the `-v` option just helps to trace what's happening.

Also note multicast global scope (224.2.127.254) vs. administered scope which devices typically assume to be
239.255.255.255.
### `sdp-parse`

```
Usage: ./sdp-parse ([-h?] | [-t [-brc]])
Attempts to parse SDP incoming on STDIN (primarily useful to validate SDP files quickly).
Options:
	 -h	 Prints this info
	 -d	 Prints some debug info to STDERR
	 -t	 Test if the first (SDP) packet (and only the first) contains at least one valid stream; return 0 if valid, >0 otherwise
	 -b	 Filter by bitwidth/encoding (8/16/24/32/AM824, representing L8, L16, L24, L32, AM824 respectively)
	 -r	 Filter by sampling rate (frequency); ex. 48000
	 -c	 Filter by number of channels required
```

### `sdp-gen`
```
Usage:
	 ./sdp-gen [-h?]
	 ./sdp-gen [options...] <src-host> <dst-ip>[:<rtp-port>]
Generator for quick and dirty single-stream SDP generation.
Arguments:
	 <src-host>			 IPv4/v6 or hostname of SDP originator host (see --src-ipver to explicitly set ip version)
	 <target-ip-port>		 IPv4/v6 of sending/receiving host
Options:
	 -h, -?				 Prints this info
	 --src-ipver <ipver>		 Explicitly sets SDP originator IP version (4, default, or 6)
	 --id <id>			 Session ID (U32, default 1)
	 --version <version>		 Session version (U32, default 1)
	 -n, --name <name>		 Name of session (default none)
	 -i, --info <info>		 Further session info (default none)
	 --ptp-domain <domain>		 (RAVENNA) PTP domain (u7, default none)
	 -m, --mode <mode>		 Stream mode, most likely you will use "recv" (default, for recipient to be receiving only, ie you will be sending)
	 -b <bitrate>			 'Bitrate' of encoding, values 8/16/24/32/AM824 accepted only (default 24)
	 -r <rate>			 Samplerate (default 48000)
	 -c <nchannels>			 Number of channels (default 2)
	 --ttl <ttl>			 IPv4 multicasting TTL override (default 32)
	 --ptime <ptime>		 ptime value as millisec float (default 1.0)
	 --refclk-localmac <mac>	 Ethernet MAC (XX-XX-XX-XX-XX)
	 --ptp-traceable		 Default reference clock!
	 --ptp-clock <ptp-std>:<ptp-eui64>[:<ptp-domain>]
		 <ptp-std> := 1588-2002|1588-2008|1588-2019|802.1AS-2011
		 <ptp-eui64> := XX-XX-XX-XX-XX-XX-XX-XX
	 --mediaclk-offset <offset>	 Mediaclock offset (default 0)
```
With default settings for command `./sdp-gen 10.0.0.2 224.0.0.12`:
```
v=0
o=- 1 1 IN IP4 10.0.0.2
s=
c=IN IP4 224.0.0.1/32
t=0 0
a=tool:caes67
a=ts-refclk:ptp=traceable
a=recvonly
m=audio 5004 RTP/AVP 96
a=rtpmap:96 L24/48000/2
a=ptime:1
a=mediaclk:direct=0
```

### `rtsp-describe`
```
Usage: ./rtsp-describe [-r] [<rtsp-url>]
Attempts to retrieve SDP header from given RTSP URL(s) (rtsp://<host>[:<port>][<resource>])
and prints to STDOUT. If no <rtsp-url> is given assumes there will be one rtsp-url per line
on STDIN.
Options:
	 -h,-?	 Prints this info
	 -r	 Prints RTSP header info to STDERR
Example:
./rtsp-describe -r rtsp://192.168.2.138:9090/by-name/here-be-kittens-ravenna_1
```
Note that there is also a quick and dirty script for this, although it is less reliable.

### `rav-lookup`
```
Usage: rav-lookup [-h?] | [-v] [-s|--sessions] [-d|--devices] [--receivers] [--senders] [--filter (disco|term)] [-n]
Outputs any found session, receivers or senders as found per mDNS requests to STDOUT.
One result per line:
	session: rtsp://<host>:<port>/by-name/<session-name>
	senders: rtsp://<host>:<port>
	receivers: http://<host>:<port>
If neither type is explicitly requested, looks for sessions only.
Options:
	 -h,-?		 Outputs this info
	 -v		 Some status output to STDERR
	 -s,--sessions	 Browse for sessions
	 --receivers	 Browse for receiving devices
	 --senders	 Browse for sending devices
	 -d,--devices	 Browse for senders and receivers (shortcut for --receivers --senders)
	 -f,--filter (disco|term)
			 Show discovered or terminated services only (default disco)
	 -n, --no-enc	 Do not urlencode (session name, ie print as is)
```
Just a comfort utility, using `dns-sd` you could also discover services:

```bash
# sessions -> rtsp://<host>:<port>/by-name/<ravenna-session-name>
dns-sd -Z _rtsp._tcp,_ravenna_session

# general ravenna compatible devices
dns-sd -Z _rtsp._tcp,_ravenna
dns-sd -Z _http._tcp,_ravenna
```
Or similarly using `avahi-browse`
```bash
avahi-browse -r _ravenna_session._sub._rtsp._tcp
avahi-browse -r _ravenna._sub._rtsp._tcp
avahi-browse -r _ravenna._sub._http._tcp
```

To quickly register a (test) ravenna session with name `Hello my pretty` on the localhost's port 9191:
```bash
dns-sd -R "Hello my pretty" _rtsp._tcp,_ravenna_session local 9191
avahi-publish -s "Hello my pretty" _rtsp._tcp 9191 --sub _ravenna_session._sub._rtsp._tcp
```

Please note, that actual Ravenna devices expect to find an actual RTSP service on said host and port
with an SDP resource retrievable through an RTSP *DESCRIBE* request for URI `/by-name/Hello%20my%20pretty`
(URL encoded session name).

## References

- [AES67-2018 Standard document](https://www.aes.org/publications/standards/search.cfm?docID=96)
- [IEEE1558-2019 (PTPv2.1) Standard document](https://standards.ieee.org/content/ieee-standards/en/standard/1588-2019.html)
- https://en.wikipedia.org/wiki/AES67
- https://hartung.io/2020/07/aes67-resources/ (nice collection of resources)

## License

Copyright (C) 2021  Philip Tschiemer

GNU Affero General Public License v3
