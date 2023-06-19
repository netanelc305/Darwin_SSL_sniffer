import binascii
from dataclasses import dataclass, field
from typing import List, Tuple

from iosslsniffer.syslog_parser import SyslogParser
from iosslsniffer.tcp_simulation import TCPSession


@dataclass(repr=True)
class SSLSession:
    """ Collect all SSL messages of active fd """
    fd: int
    src: Tuple[str, int]
    dst: Tuple[str, int]
    _streams: List[SyslogParser] = field(default_factory=list)

    def process(self, msg: SyslogParser) -> None:
        """ Save SSL messages into list """
        self._streams.append(msg)

    def dump(self, out_file: str) -> None:
        """ Dump all SSL streams into pcapng with TCP Simulation """
        with TCPSession(self.src, self.dst) as session:
            for stream in self._streams:
                data = binascii.unhexlify(stream.body)
                if stream.method == 'SSL-SEND':
                    session.send(data, '>')
                elif stream.method == 'SSL-READ':
                    session.send(data, '<')
        session.dump(out_file, append=True)
