# MUD URL Validator

> **DO NOT COMMIT THIS TEXT BLOCK UPSTREAM**
>
> This repository includes a **temporary fork**, maintained by @iggy2028, 
> of the dpkt repository. This fork adds support for LLDP to dpkt. This
> fork is in support of the MUD URL Validator also included in this
> repository.

MUD URL Validator
-----------------

The MUD URL Validator is a python script that finds each Ethernet frame in a 
PCAP file that contains a MUD URL. It then validates that the MUD URL is
properly formed according to the MUD specification
(https://tools.ietf.org/html/draft-ietf-opsawg-mud).

The Validator will look for a MUD URL in an LLDP message, 
a DHCP Discover message, and a DHCP Request message.

#### Requirements:
* version >= Python 2.6 or Python3
* dpkt (from this repository)
* validators

#### Installation:

Install dependancies

	pip install validators

(Note: Depending on your system, you may need to run pip as root. In that 
case prepend each command with "sudo".)
	

Install dpkt from this repository, which supports LLDP.

	pip install -e ./dpkt

or 

	cd dpkt
	python setup.py install

You will also be using the validate_mud_url.py script, which can be copied to any
directory that you like.

### Usage

1. Capturing Packets

You will need to create a PCAP file, for example using using Wireshark or
tcpdump.  Care must be taken that the capture device has access to the
packets being generated. 

To capture DHCP packets, the capture device needs to be on the routed path 
between the device emitting the DHCP packets and the DHCP server. 
DHCP packets are IP packets. It may work to connect the capture device 
to another port on the switch to which the device is attached.

Capturing LLDP packets takes a little more care because they are emitted 
on Ethernet group addresses that are consumed by the Ethernet switch. As such,
they are only available on the port between the device emitting the LLDP 
packets and the switch port to which it is connected. So if you are 
validating a MUD URL in an LLDP packet, you'll need to install an Ethernet 
hub on that port, or configure a "SPAN" port on the switch 
being sent properly in LLDP packets. But if the device is drawing power 
from the switch (using PoE), then you'll need to use the "SPAN" port approach.

To create a SPAN port on a Cisco Catalyst switch, configure a 
"monitor session". For example, if you are inspecting packets from a device
connected to GigabitEthernet1/0/4, and capturing them on
GigabitEthernet1/0/14, you would configure the following in the configuration:

	monitor session 1 source interface Gi1/0/4
	monitor session 1 destination interface Gi1/0/14

Save the resulting file in a PCAP format (i.e., with a '.pcap' file
extension). If you using WireShark this is not its default format.

2. Discover and validate MUD URLs in the PCAP file.

Run the validate_mud_url.py as follows:

	python validate_mud_url.py <filename>.pcap

For each packet in which a MUD URL was found, the Ethernet header and other
information is displayed, followed by the MUD URL, and a validation note. If
the validation note is "OK!", then the MUD URL was found to be properly
formed. If the validation note begins with "ERROR", then you will need to
adjust the MUD URL as it is emitted by the device.

### Contributors
[Brian Weis](https://github.com/iggy2028)
