import random
import re
from typing import List, Union
from xml.dom.minidom import parseString

import requests

from upnpfuzz.display import print_error, print_status
from upnpfuzz.generators.base import BaseGenerator
from upnpfuzz.utils import parse_url

TIMEOUT = 10


class NewSubscribe:
    """
    Represents new subscribe request.
    """
    def __init__(self, event, host, port, callback):
        """
        Initializes new subscribe request.

        Args:
            event (str): The event path.
            host (str): The target host address.
            port (int): The target port number.
            callback (str): The callback address that should be used.
        """
        self.event = event.encode("utf-8")
        self.host = host.encode("utf-8")
        self.port = str(port).encode("utf-8")
        self.callback = callback.encode("utf-8")

    def get_headers_params(self) -> List[bytes]:
        """
        Retrieves the new subscribe request params.

        Returns:
            List[bytes]: The list of params for the new subscribe request.
        """
        headers_params = [
            self.event,
            self.host, self.port,
            self.callback,
            b"upnp:event",
            b"Second-7200",
        ]
        return headers_params

    @staticmethod
    def finalize_headers(headers_params: List[bytes]) -> bytes:
        """
        Finalizes the request by inserting headers params into the request.

        Returns:
            bytes: The finalized new subscribe request.
        """
        event, host, port, callback, nt, timeout = headers_params
        request = (
            b"SUBSCRIBE " + event + b" HTTP/1.1\r\n" +
            b"HOST: " + host + b":" + port + b"\r\n" +
            b"CALLBACK: " + b"<" + callback + b">\r\n" +
            b"NT: " + nt + b"\r\n" +
            b"TIMEOUT: " + timeout + b"\r\n" +
            b"\r\n"
        )
        return request


class RenewalSubscribe:
    """
    Represents renewal subscribe request.
    """
    def __init__(self, event: str, host: str, port: int, sid: bytes):
        """
        Initializes the renewal subscribe request.

        Args:
            event (str): The event path.
            host (str): The target host address.
            port (int): The target port number.
            sid (bytes): The sid identifier.
        """
        self.event = event.encode("utf-8")
        self.host = host.encode("utf-8")
        self.port = str(port).encode("utf-8")
        self.sid = sid

    def get_headers_params(self) -> List[bytes]:
        """
        Retrieves the renewal subscribe request params.

        Returns:
            List[bytes]: The list of params for the renewal subscribe request.
        """
        headers_params = [
            self.event,
            self.host, self.port,
            self.sid,
            b"Second-3600"
        ]
        return headers_params

    @staticmethod
    def finalize_headers(headers_params: List[bytes]) -> bytes:
        """
        Finalizes the request by inserting headers params into the request.

        Returns:
            bytes: The finalized renewal subscribe request.
        """
        event, host, port, sid, timeout = headers_params
        request = (
            b"SUBSCRIBE " + event + b" HTTP/1.1\r\n" +
            b"HOST: " + host + b":" + port + b"\r\n" +
            b"SID: " + sid + b"\r\n" +
            b"TIMEOUT: " + timeout + b"\r\n" +
            b"\r\n"
        )
        return request


class Unsubscribe:
    """
    Represents unsubscribe request.
    """
    def __init__(self, event: str, host: str, port: int, sid: bytes):
        """
        Initializes the unsubscribe request.

        Args:
            event (str): The event path.
            host (str): The target host address.
            port (int): The target port number.
            sid (bytes): The sid identifier.
        """
        self.event = event.encode("utf-8")
        self.host = host.encode("utf-8")
        self.port = str(port).encode("utf-8")
        self.sid = sid

    def get_headers_params(self) -> List[bytes]:
        """
        Retrieves the unsubscribe request params.

        Returns:
            List[bytes]: The list of params for the unsubscribe request.
        """
        headers_params = [
            self.event,
            self.host, self.port,
            self.sid
        ]
        return headers_params

    @staticmethod
    def finalize_headers(headers_params: List[bytes]) -> bytes:
        """
        Finalizes the request by inserting headers params into the request.

        Returns:
            bytes: The finalized unsubscribe request.
        """
        event, host, port, sid = headers_params
        request = (
            b"UNSUBSCRIBE " + event + b" HTTP/1.1\r\n" +
            b"HOST: " + host + b":" + port + b"\r\n" +
            b"SID: " + sid + b"\r\n" +
            b"\r\n"
        )
        return request


class ESPGenerator(BaseGenerator):
    """
    Generates ESP requests.
    """
    name = "esp"

    def __init__(self, url: str, callback: str):
        """
        Initializes the ESPGenerator.

        Args:
            url: The address where the grammar should be pulled from.
        """
        self.events = []
        self.sids = {}
        self.event = ""
        self.callback = callback
        self.url = url
        _, self.host, self.port = parse_url(url)

    def generate_grammar(self) -> bool:
        """
        Generates grammar for ESP.

        Returns:
            bool: Returns true if generating grammar was successful or false it failed.
        """
        print_status(f"requesting: {self.url}")
        try:
            response = requests.get(self.url, timeout=TIMEOUT)
        except requests.exceptions.RequestException:
            print_error("failed to retrieve the xml")
            return False

        xml = parseString(response.content)

        for device in xml.getElementsByTagName("device"):
            for service in device.getElementsByTagName("service"):
                event_sub_url = service.getElementsByTagName("eventSubURL")[0].firstChild.data

                if not event_sub_url.startswith("/"):
                    event_sub_url = "/" + event_sub_url

                self.events.append(event_sub_url)

        return True if self.events else False

    def handle_sid(self, response: bytes) -> None:
        """
        Handles SID tracking during subscriptions.

        Args:
            response (bytes): The response that was returned to extract SID from.
        """
        res = re.search(b"SID: (.*?)\r\n", response)
        if res:
            sid = res.group(1)
            self.sids[sid] = self.event

    def get_request(self) -> Union[NewSubscribe, RenewalSubscribe, Unsubscribe]:
        """
        Retrieve random request that will be fuzzed.

        Returns:
            Union[NewSubscribe, RenewalSubscribe, Unsubscribe]: Random request object.
        """
        get_request = random.choice(
            [self.get_new_subscribe_request, self.get_renewal_subscribe_request, self.get_unsubscribe_request]
        )

        return get_request()

    def get_new_subscribe_request(self) -> NewSubscribe:
        """
        Generate new subscribe request for the random event.

        Returns:
            NewSubscribe: The new subscribe request.
        """
        self.event = random.choice(self.events)
        return NewSubscribe(self.event, self.host, self.port, self.callback)

    def get_renewal_subscribe_request(self) -> RenewalSubscribe:
        """
        Generate renewal subscribe request for one of the tracked SIDs

        Returns:
            RenewalSubscribe: The renewal subscribe request.
        """
        all_sids = [sid for sid in self.sids.keys()]
        sid = random.choice(all_sids) if all_sids else None
        if sid:
            event = self.sids[sid]
        else:
            sid = b"uuid:1234-5678-90ab-cdef"
            event = random.choice(self.events)

        return RenewalSubscribe(event, self.host, self.port, sid)

    def get_unsubscribe_request(self) -> Unsubscribe:
        """
        Generate unsubscribe request for one of the tracked SIDs

        Returns:
            Unsubscribe: The unsubscribe request.
        """
        all_sids = [sid for sid in self.sids.keys()]
        sid = random.choice(all_sids) if all_sids else None
        if sid:
            event = self.sids[sid]
            del self.sids[sid]
        else:
            sid = b"uuid:1234-5678-90ab-cdef"
            event = random.choice(self.events)

        return Unsubscribe(event, self.host, self.port, sid)
