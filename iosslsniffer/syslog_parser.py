import re
from collections import namedtuple
from typing import NamedTuple, Tuple

import parse

from iosslsniffer.exceptions import ParseFailedError


class SyslogParser:
    """ Parse syslog messages related to SSL """
    PATTERN = (
        '{date} iPhone {filename}({image_name})[{pid:d}] <Notice>: CFNetwork Diagnostics [{}:{msg_id:d}] {} {\n'
        '{ fd: {fd:d}, local {local:Local} => peer {peer:Peer} {domain}} {method} {extra}: (null)\n'
        '{} data [ {data_size:d} ] bytes {\n{body:Body}}\n} [{}]')

    HEXDUMP = r'\d{8}:\s?(.+?)(?=\s{4})'

    @staticmethod
    def parse(message: str) -> NamedTuple:
        """ Parse ssl message according to the message format """
        parsed = parse.parse(SyslogParser.PATTERN, message,
                             dict(Local=SyslogParser._parse_address,
                                  Peer=SyslogParser._parse_address,
                                  Body=SyslogParser._parse_body))
        if not parsed:
            raise ParseFailedError()
        parsed = parsed.named
        return namedtuple('SyslogSSLParser', parsed.keys())(*parsed.values())

    @staticmethod
    def _parse_body(body: str) -> str:
        """ Parse the ssl message body """
        dump = re.findall(SyslogParser.HEXDUMP, body)
        dump = ''.join([x.replace(' ', '') for x in dump])
        return dump

    @staticmethod
    def _parse_address(addr_str: str) -> Tuple[str, int]:
        """ Parse ip:port pairs """
        ip, port = addr_str.split(':')
        if '/' in port:
            port, _ = port.split('/')
        return ip, int(port)
