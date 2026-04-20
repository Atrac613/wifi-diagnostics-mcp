from __future__ import annotations

import logging
import socketserver
import threading
from datetime import datetime
from typing import Callable

from .config import AppConfig
from .models import utc_now


SyslogCallback = Callable[[str, str, datetime], None]
logger = logging.getLogger(__name__)


class _ThreadingUDPServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True

    def __init__(self, server_address: tuple[str, int], callback: SyslogCallback) -> None:
        self.callback = callback
        super().__init__(server_address, _UDPHandler)


class _ThreadingTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True

    def __init__(self, server_address: tuple[str, int], callback: SyslogCallback) -> None:
        self.callback = callback
        super().__init__(server_address, _TCPHandler)


class _UDPHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data = self.request[0]
        message = data.decode("utf-8", errors="replace").strip()
        if message:
            self.server.callback(message, self.client_address[0], utc_now())


class _TCPHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        while True:
            raw_line = self.rfile.readline()
            if not raw_line:
                break
            message = raw_line.decode("utf-8", errors="replace").strip()
            if message:
                self.server.callback(message, self.client_address[0], utc_now())


class SyslogReceiverManager:
    def __init__(self, config: AppConfig, callback: SyslogCallback) -> None:
        self.config = config
        self.callback = callback
        self._udp_server: _ThreadingUDPServer | None = None
        self._tcp_server: _ThreadingTCPServer | None = None
        self._threads: list[threading.Thread] = []

    def start(self) -> None:
        self._udp_server = _ThreadingUDPServer(("0.0.0.0", self.config.syslog_udp_port), self.callback)
        udp_thread = threading.Thread(
            target=self._udp_server.serve_forever,
            name="wifi-syslog-udp",
            daemon=True,
        )
        udp_thread.start()
        self._threads.append(udp_thread)
        logger.info("UDP syslog receiver listening on %s", self.config.syslog_udp_port)

        if self.config.enable_tcp_syslog:
            self._tcp_server = _ThreadingTCPServer(("0.0.0.0", self.config.syslog_tcp_port), self.callback)
            tcp_thread = threading.Thread(
                target=self._tcp_server.serve_forever,
                name="wifi-syslog-tcp",
                daemon=True,
            )
            tcp_thread.start()
            self._threads.append(tcp_thread)
            logger.info("TCP syslog receiver listening on %s", self.config.syslog_tcp_port)

    def stop(self) -> None:
        if self._udp_server is not None:
            self._udp_server.shutdown()
            self._udp_server.server_close()
        if self._tcp_server is not None:
            self._tcp_server.shutdown()
            self._tcp_server.server_close()

