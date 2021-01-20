# aes67
Framework for AES67 targeting embedded devices.

WORK IN PROGRESS

Designed in particular to be employed on embedded devices and thus not relying on dynamic memory allocation (although optionally possible where meaningful), tight control over memory usage, no dependencies on external libraries, in particular as few hardware/library abstractions are used as possible - the framework will have to be adapted according to needs.

Components are intended to be as minimal as possible to allow for essential AES67 operations and be as interoperable as possible - in detail this is not yet clear and requires further investigation into different manufacturer-dependent implementations.

https://github.com/tschiemer/aes67

## Rough feature/support roadmap

- Clock
  - [ ] PTPv2 / IEEE1558-2008 ?
  - [ ] PTPv2.1 / IEEE1558-2019 ??
- Discovery & | Management
  - [ ] SAP (required for interoperability)
  - [mDNS / DNS-SD](https://github.com/tschiemer/minimr)
  - [ ] SIP ? (for unicast management according to standard, but most systems use multicast only..)
  - [ ] RSTP ?
  - [NMOS](https://github.com/AMWA-TV/nmos)
  - [AES70/OCA](https://github.com/tschiemer/ocac) *work in progress*
- Stream
  - [ ] RTP/RTCP

- command line / developer utilities


## References

- [AES67-2018 Standard document](https://www.aes.org/publications/standards/search.cfm?docID=96)
- [IEEE1558-2019 (PTPv2.1) Standard document](https://standards.ieee.org/content/ieee-standards/en/standard/1588-2019.html)
- https://en.wikipedia.org/wiki/AES67
- https://hartung.io/2020/07/aes67-resources/ (nice collection of resources)

## License

Copyright (C) 2021  Philip Tschiemer

GNU Affero General Public License v3
