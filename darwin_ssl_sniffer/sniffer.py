import logging
import os
import posixpath
from dataclasses import dataclass
from typing import Tuple

import coloredlogs
from maclog.log import get_logger
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.services.syslog import SyslogService

from darwin_ssl_sniffer.exceptions import ParseFailedError
from darwin_ssl_sniffer.ssl_session import SSLSession
from darwin_ssl_sniffer.syslog_parser import HostSyslogParser, MobileSyslogParser

coloredlogs.install(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class EntryHash:
    pid: int
    process_name: str
    image: str
    domain: str


@dataclass(repr=True)
class Filters:
    pids: Tuple = None
    process_names: Tuple = None
    images: Tuple = None
    black_list: bool = True

    def should_keep(self, entry_hash: EntryHash) -> bool:
        """ Filter out entry if one of the criteria specified (pid,image,process_name) """
        in_filters = (
                self.pids is not None and entry_hash.pid in self.pids or
                self.process_names is not None and entry_hash.process_name in self.process_names or
                self.images is not None and entry_hash.image in self.images
        )

        return self.black_list and not in_filters or not self.black_list and in_filters


@dataclass
class FdEntry:
    entry_hash: EntryHash
    ssl_session: SSLSession


class MobileSniffer:
    def __init__(self, lockdown: LockdownServiceProvider, out_file: str, filters=None):
        self.lockdown = lockdown
        self.os_trace_service = SyslogService(self.lockdown)
        self.syslog_parser = MobileSyslogParser()
        self.active_fd = {}
        self._filters = filters
        self._out_file = out_file

    def sniff(self) -> None:
        logger.info(f'Active filters {self._filters}')
        logger.info('Waiting for traffic...')

        for entry in self.os_trace_service.watch():
            if 'CFNetwork' not in entry:
                continue

            if 'done using Connection' in entry:
                fd = int(entry.split()[-1])
                if fd in self.active_fd:
                    fd_entry = self.active_fd[fd]
                    logger.info(
                        f'Saving recording for {fd_entry.entry_hash.process_name}({fd_entry.entry_hash.pid})  💾  '
                        f'{fd_entry.entry_hash.domain}')
                    fd_entry.ssl_session.dump(self._out_file)
                    self.active_fd.pop(fd)

            if 'SSL' not in entry:
                continue
            try:
                parsed = self.syslog_parser.parse(entry)
            except ParseFailedError:
                continue

            entry_hash = EntryHash(parsed.pid,
                                   posixpath.basename(parsed.filename),
                                   os.path.basename(parsed.image_name),
                                   parsed.domain)

            if not self._filters.should_keep(entry_hash):
                logger.warning(
                    f'Ignoring traffic ❌ {entry_hash.process_name}({parsed.pid}) {entry_hash.domain}')
                continue

            fd = parsed.fd
            if fd not in self.active_fd:
                logger.info(
                    f'Recording SSL traffic {entry_hash.process_name}({parsed.pid}) ➡️  {entry_hash.domain}')
                self.active_fd[fd] = FdEntry(entry_hash, SSLSession(fd, parsed.local, parsed.peer))

            self.active_fd[fd].ssl_session.process(parsed)


class HostSniffer:
    def __init__(self, out_file: str, filters=None):
        self.syslog_parser = HostSyslogParser()
        self.active_fd = {}
        self._filters = filters
        self._out_file = out_file

    def sniff(self) -> None:
        logger.info(f'Active filters {self._filters}')
        logger.info('Waiting for traffic...')

        for entry in get_logger():
            if 'CFNetwork' not in str(entry.sender_image_path):
                continue

            if 'done using Connection' in entry.event_message:
                fd = int(entry.event_message.split()[-1])
                if fd in self.active_fd:
                    fd_entry = self.active_fd[fd]
                    logger.info(
                        f'Saving recording for {fd_entry.entry_hash.process_name}({fd_entry.entry_hash.pid})  💾  '
                        f'{fd_entry.entry_hash.domain}')
                    fd_entry.ssl_session.dump(self._out_file)
                    self.active_fd.pop(fd)

            if 'SSL' not in entry.event_message:
                continue
            try:
                parsed = self.syslog_parser.parse(entry.event_message)
            except ParseFailedError:
                continue

            entry_hash = EntryHash(entry.process_id,
                                   entry.process_image_path.parts[-1],
                                   entry.sender_image_path.parts[-1],
                                   parsed.domain)

            if not self._filters.should_keep(entry_hash):
                logger.warning(
                    f'Ignoring traffic ❌ {entry_hash.process_name}({parsed.pid}) {entry_hash.domain}')
                continue

            fd = parsed.fd
            if fd not in self.active_fd:
                logger.info(
                    f'Recording SSL traffic {entry_hash.process_name}({entry.process_id}) ➡️  {entry_hash.domain}')
                self.active_fd[fd] = FdEntry(entry_hash, SSLSession(fd, parsed.local, parsed.peer))

            self.active_fd[fd].ssl_session.process(parsed)
