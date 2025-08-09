# RFC 1483/2684 packet dissector in ATM over TCP protocol for Wireshark

A simple dissector that allows you to view RFC 1483/2684 compliant packets (e.g. PPPoA, Ethernet, IPv4, IPv6) transmitted using the ATM over TCP protocol.

By default, it connects to port 2812 where ATMoTCP is running and registers a new protocol `atmotcp`, unlike the built-in Wireshark `atmtcp`, which does not support RFC 1483/2684 packets.
