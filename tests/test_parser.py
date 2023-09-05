"""Tests for SyslogParser"""

from darwin_ssl_sniffer.syslog_parser import SyslogParser

MSG = ('Jun 19 01:04:37 iPhone apsd(CFNetwork)[157] <Notice>: CFNetwork Diagnostics [3:9376] 01:04:37.469 {\n'
       '{ fd: 2, local 127.0.0.1:49757 => peer 127.0.0.1:5223 testdomain.com} SSL-READ 4: (null)\n'
       'SSL-READ (2) | < data [ 4 ] bytes {\n'
       'SSL-READ (2) | < 00000000: 0d02 0181                                  -...            \n'
       'SSL-READ (2) | < }\n'
       '} [3:9376]')


def test_parser():
    parsed = SyslogParser.parse(MSG)
    assert parsed is not None
    assert parsed.filename == 'apsd'
    assert parsed.image_name == 'CFNetwork'
    assert parsed.pid == 157
    assert parsed.msg_id == 9376
    assert parsed.fd == 2
    assert parsed.local == ('127.0.0.1', 49757)
    assert parsed.peer == ('127.0.0.1', 5223)
    assert parsed.domain == 'testdomain.com'
    assert parsed.method == 'SSL-READ'
    assert parsed.extra == '4'
    assert parsed.data_size == 4
    assert parsed.body == '0d020181'
