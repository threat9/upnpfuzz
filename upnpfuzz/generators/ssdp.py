import random
from typing import List, Union

from upnpfuzz.generators.base import BaseGenerator


def get_user_agent() -> bytes:
    """
    Retrieve random user agent.

    Returns:
         bytes: The random user agent.
    """
    user_agents = [
        "Windows/10.0 UPnP/1.1 MyClient/1.0",
        "Linux/5.4 UPnP/1.1 VLC/3.0",
        "Android/11 UPnP/1.1 BubbleUPnP/3.5.4",
        "MacOS/12.3 UPnP/1.1 UPnP-Inspector/0.2",
        "IoTDevice/1.0 UPnP/1.1 GenericDevice/2.0",
        "Xbox/10.0 UPnP/1.1 XboxUPnP/1.0",
        "PrinterOS/2.1 UPnP/1.1 PrinterService/1.5",
        "CustomScript/1.0 UPnP/1.1 TestTool/1.2",
        "RouterOS/6.49 UPnP/1.1 MiniUPnPd/2.2.1",
        "SmartTV/1.0 UPnP/1.1 DLNADOC/1.50",
    ]
    return random.choice(user_agents).encode("utf-8")


def get_mx() -> bytes:
    """
    Retrieves random MX header value.

    Returns:
        bytes: The random MX header value.
    """
    num = random.randint(1, 5)
    return str(num).encode("utf-8")


def get_st() -> bytes:
    """
    Retrieves random ST header value.

    Returns:
        bytes: The random ST header value.
    """
    sts = [
        "ssdp:all",
        "upnp:rootdevice"
    ]
    return random.choice(sts).encode("utf-8")


class SearchRequest:
    def __init__(self, host: str, port: int):
        """
        Initializes the search request.

        Args:
            host (str): The target host address.
            port (int): The target port number.
        """
        self.host = host.encode("utf-8")
        self.port = str(port).encode("utf-8")

    def get_headers_params(self) -> List[bytes]:
        """
        Retrieves the request params.

        Returns:
            List[bytes]: The list of request params.
        """
        headers_params = [
            self.host, self.port,
            b"ssdp.discover",
            get_mx(),
            get_st(),
            get_user_agent(),
        ]
        return headers_params

    @staticmethod
    def finalize_headers(headers_params: List[bytes]) -> bytes:
        """
        Finalizes the request by filling it with the params.

        Args:
            headers_params (List[bytes]): The params used for request.

        Returns:
            bytes: The finalized request.
        """
        host, port, man, mx, st, user_agent = headers_params
        request_headers = (
            b"M-SEARCH * HTTP/1.1\r\n" +
            b"HOST: " + host + b":" + port + b"\r\n" +
            b"MAN: \"" + man + b"\"\r\n" +
            b"MX: " + mx + b"\r\n" +
            b"ST: " + st + b"\r\n" +
            b"USER-AGENT: " + user_agent + b"\r\n" +
            b"\r\n"
        )
        return request_headers


class NotifyRequest:
    def __init__(self, host: str, port: int):
        """
        Initializes the search request.

        Args:
            host (str): The target host address.
            port (int): The target port number.
        """
        self.host = host.encode("utf-8")
        self.port = str(port).encode("utf-8")

    def get_headers_params(self) -> List[bytes]:
        """
        Retrieves the request params.

        Returns:
            List[bytes]: The list of request params.
        """
        headers_params = [
            self.host, self.port,
            b"upnp:rootdevice",
            b"ssdp:alive",
            b"uuid:device-UUID::upnp:rootdevice",
            b"http://192.168.1.2:80/device.xml",
            b"max-age=1800",
            get_user_agent(),
            b"1",
            b"1337",
        ]
        return headers_params

    @staticmethod
    def finalize_headers(headers_params: List[bytes]) -> bytes:
        """
        Finalizes the request by filling it with the params.

        Args:
            headers_params (List[bytes]): The params used for request.

        Returns:
            bytes: The finalized request.
        """
        host, port, nt, nts, usn, location, cache_control, server, bootid, configid = headers_params
        request_headers = (
            b"NOTIFY * HTTP/1.1\r\n" +
            b"HOST: " + host + b":" + port + b"\r\n" +
            b"NT: " + nt + b"\r\n" +
            b"NTS: " + nts + b"\r\n" +
            b"USN: " + usn + b"\r\n" +
            b"LOCATION: " + location + b"\r\n" +
            b"CACHE-CONTROL: " + cache_control + b"\r\n" +
            b"SERVER: " + server + b"\r\n" +
            b"BOOTID.UPNP.ORG: " + bootid + b"\r\n" +
            b"CONFIGID.UPNP.ORG: " + configid + b"\r\n" +
            b"\r\n"
        )
        return request_headers


class SSDPGenerator(BaseGenerator):
    """
    Generates the SSDP requests.
    """
    name = "ssdp"

    def __init__(self, host: str, port: int):
        """
        Initializes the SSDP generator.

        Args:
            host (str): The target host address.
            port (int): The target port number.
        """
        self.host = host
        self.port = port

    def get_multicast_request(self) -> bytes:
        """
        Retrieves search multicast request used for discovering UPnP devices in the network.

        Returns:
            bytes: The search multicast request.
        """
        multicast_request = (
            b"M-SEARCH * HTTP/1.1\r\n" +
            b"HOST: 239.255.255.250:1900\r\n" +
            b"MAN: \"ssdp:discover\"\r\n" +
            b"MX: 1\r\n" +
            b"ST: ssdp:all\r\n" +
            b"USER-AGENT: " + get_user_agent() + b"\r\n" +
            b"\r\n"
        )
        return multicast_request

    def get_request(self) -> Union[SearchRequest, NotifyRequest]:
        """
        Retrieves random request either search or notify request.

        Returns:
            Union[SearchRequest, NotifyRequest]: Random search or notify request.
        """
        request = random.choice([
            SearchRequest,
            NotifyRequest
        ])
        return request(self.host, self.port)
