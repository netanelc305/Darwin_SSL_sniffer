import logging
import random
from typing import Tuple

# flake8: noqa E402
logging.getLogger('scapy.runtime').disabled = True

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Packet, Raw
from scapy.utils import wrpcap


class TCPPeer:
    """ Simulate a TCP Peer """

    def __init__(self, src: Tuple[str, int], dst: Tuple[str, int]):
        self.seq_next = random.randrange(0, (2 ** 32) - 1)
        self.template = Ether() / IP(src=src[0], dst=dst[0]) / TCP(sport=src[1], dport=dst[1])

    def ack(self, ack: int) -> Packet:
        """ Send ACK packt """
        return self._pkt('A', ack)

    def push(self, data: bytes = b'') -> Packet:
        """ Send PUSH packt with payload """
        pkt = self._pkt('P') / Raw(load=data)
        self.seq_next += len(data)
        return pkt

    def syn(self) -> Packet:
        """ Send SYN packt """
        pkt = self._pkt('S')
        self.seq_next += 1
        return pkt

    def syn_ack(self, ack: int) -> Packet:
        """ Send SYN/ACK packt """
        pkt = self._pkt('SA', ack)
        self.seq_next += 1
        return pkt

    def fin(self) -> Packet:
        """ Send FIN packt """
        pkt = self._pkt('F')
        self.seq_next += 1
        return pkt

    def _pkt(self, flags: str, ack: int = None) -> Packet:
        """ Packet builder """
        pkt = self.template.copy()

        if ack is not None:
            pkt[TCP].ack = ack

        pkt[TCP].seq = self.seq_next
        pkt[TCP].flags = flags

        return pkt


class TCPSession:
    """ Simulate TCP Session between 2 peers """

    def __init__(self, src: Tuple[str, int], dst: Tuple[str, int]):
        self.src = TCPPeer(src, dst)
        self.dst = TCPPeer(dst, src)
        self.ack = None
        self.pkts = []

    def handshake(self) -> None:
        """ Simulate 3 way handshake """
        self.pkts.append(self.src.syn())
        self.pkts.append(self.dst.syn_ack(self.pkts[-1][TCP].seq))
        self.pkts.append(self.src.ack(self.pkts[-1][TCP].seq))

    def send(self, data: bytes, direction: str = '>') -> None:
        """ Simulate send from peerX to peerY vice versa """
        if direction == '>':
            self._send(self.src, self.dst, data)
        elif direction == '<':
            self._send(self.dst, self.src, data)

    def _send(self, p1: TCPPeer, p2: TCPPeer, data: bytes) -> None:
        """ Simulate send from peerX to peerY and ACK from peerY """
        self.pkts.append(p1.push(data=data))
        self.pkts.append(p2.ack(self.pkts[-1][TCP].seq))

    def close(self) -> None:
        """ Simulate session close """
        self.pkts.append(self.src.fin())
        self.pkts.append(self.dst.ack(self.pkts[-1][TCP].seq))
        self.pkts.append(self.dst.fin())
        self.pkts.append(self.src.ack(self.pkts[-1][TCP].seq))

    def dump(self, out_file: str, append: bool = True) -> None:
        """ Dump TCP Session into a pcapng file """
        wrpcap(out_file, self.pkts, append=append)

    def __enter__(self) -> 'TCPSession':
        """ Returns TCP Session object after handshake """
        self.handshake()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """ Close TCP Session """
        self.close()
