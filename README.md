# aes67
Framework for AES67 targeting embedded devices.

WORK IN PROGRESS

Designed in particular to be employed on embedded devices and thus not relying on dynamic memory allocation (although optionally possible where meaningful), tight control over memory usage, no dependencies on external libraries, in particular as few hardware/library abstractions are used as possible - the framework will have to be adapted according to needs.

Components are intended to be as minimal as possible to allow for essential AES67 operations and be as interoperable as possible - in detail this is not yet clear and requires further investigation into different manufacturer-dependent implementations.

https://github.com/tschiemer/aes67

## Rough feature/support roadmap

- Clock
  - [ ] PTPv2 / IEEE1558-2008 ? (as per AES67-2018)
  - [ ] PTPv2.1 / IEEE1558-2019 ??
- Discovery & | Management
  - [ ] SAP (required for broader interoperability)
    - [ ] Support compression (of incoming packets)?
  - [ ] SIP ? (for unicast management according to standard, but most systems use multicast only..)
    - [x] [mDNS / DNS-SD](https://github.com/tschiemer/minimr)
  - [ ] RSTP ? (meaningful for system with Ravenna-based components if no RAV2SAP)
  - [ ] [AES70/OCA](https://github.com/tschiemer/ocac) *work in progress*
- Stream
  - [ ] RTP/RTCP

- command line / developer utilities



## In a Nutshell

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

## Utilities

- `sap-pack`
  ```
  Usage: ./sap-pack (announce|delete) <msg-hash> <origin-ip> [<payloadtype>] <sdp-file>
  Writes SAPv2 packet to STDOUT.
  ```
- `sap-unpack`
  ```
  Attempts to parse SAP packets incoming on STDIN and prints to STDOUT in the following format:
    [(announce|delete) <hash> <ip> <payload-type>]
    <payload-data>
    <newline>
  Options:
    -a	 Print SAP headers
    -h,-?	 Prints this help.
  ```

## References

- [AES67-2018 Standard document](https://www.aes.org/publications/standards/search.cfm?docID=96)
- [IEEE1558-2019 (PTPv2.1) Standard document](https://standards.ieee.org/content/ieee-standards/en/standard/1588-2019.html)
- https://en.wikipedia.org/wiki/AES67
- https://hartung.io/2020/07/aes67-resources/ (nice collection of resources)

## License

Copyright (C) 2021  Philip Tschiemer

GNU Affero General Public License v3
