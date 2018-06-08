"""IEEE 802.1AB Link Layer Discovery Protocol."""
from __future__ import absolute_import

import struct

from . import dpkt


class LLDP(dpkt.Packet):
    """Link Layer Discovery Protocol.

    See more about LLDP in IEEE 802.1AB-2016
     ttps://en.wikipedia.org/wiki/Cisco_Discovery_Protocol

    Attributes:
        tlvs: A list of TLVs found in the LLDP frame
        #TODO
    """

    # There is no header. LLDPDU consists of the first 3 mandatory TLVs
    # following the Ethertype
    __hdr__ = ()

    tlvs = ()

    class TLV(dpkt.Packet):
        __hdr__ = (
            # Type is 7 bits, Len is 9 bits
            ('typelen', 'H', 0),
        )

        def unpack(self, buf):
            dpkt.Packet.unpack(self, buf)
            tlv_len  = self.typelen & 0x01ff
            self.data = self.data[:tlv_len]

        def __len__(self):
            n = len(self.data)
            return self.__hdr_len__ + n

        def __bytes__(self):
            s = len(self)
            return self.data

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        buf = self.data
        l = []
        while buf:
            tlv = self.TLV(buf)
            l.append(tlv)
            buf = buf[len(tlv):]
        self.tlvs = l
        self.data = buf

    def __len__(self):
        return self.__hdr_len__ + sum(map(len, self.data))

    def __bytes__(self):
        data = b''.join(map(bytes, self.data))
        if not self.sum:
            self.sum = dpkt.in_cksum(self.pack_hdr() + data)
        return self.pack_hdr() + data
