import datetime
import enum
import socket
from dataclasses import dataclass

RESPONSE_DATA_BUFF_SIZE = 2048


@dataclass
class NetworkStats:
    """
    Tracks network stats.
    """
    start_time = datetime.datetime.now()
    total_requests = 0
    timeouts = 0
    errors = 0


class NetworkProtocol(enum.Enum):
    """
    Represents the network protocol.
    """
    TCP = 0
    UDP = 1


class Network:
    """
    Handles network TCP/UDP communication with the target.
    """
    def __init__(self, host: str, port: int, network_protocol: NetworkProtocol, network_timeout: float, interface_ip: str = ""):
        """
        Initializes the network instance.

        Args:
            host (str): The target IP address.
            port (int): The target port number.
            network_timeout (float): The duration before the connection times out.
        """
        self.host = host
        self.port = port
        self.network_protocol = network_protocol

        self.stats = NetworkStats()
        self.network_timeout = network_timeout
        self.interface_ip = interface_ip

        socket.setdefaulttimeout(network_timeout)

    def send(self, data: bytes) -> bytes:
        """
        Sends the data to the target using specified protocol.

        Args:
            data (bytes): The data to send.

        Returns:
            bytes: The response data.
        """
        if self.network_protocol == NetworkProtocol.TCP:
            return self.send_tcp(data)
        elif self.network_protocol == NetworkProtocol.UDP:
            return self.send_udp(data)

    def send_tcp(self, data: bytes) -> bytes:
        """
        Sends the data via TCP connection.

        Args:
            data (bytes): The data to send.

        Returns:
            bytes: The response data.
        """
        self.stats.total_requests += 1

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.connect((self.host, self.port))
                sock.sendall(data)

                response = sock.recv(RESPONSE_DATA_BUFF_SIZE)
                return response

        except socket.timeout:
            self.stats.timeouts += 1
        except socket.error:
            self.stats.errors += 1

        return b""

    def send_udp(self, data: bytes) -> bytes:
        """
        Sends the data via UDP connection.

        Args:
            data (bytes): The data to send.

        Returns:
            bytes: The response data.
        """
        self.stats.total_requests += 1

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.sendto(data, (self.host, self.port))
        except OSError:
            return b""

        while True:
            try:
                data, (ip, port) = sock.recvfrom(RESPONSE_DATA_BUFF_SIZE)
                return data
            except socket.timeout:
                self.stats.timeouts += 1
                break
            except socket.error:
                self.stats.errors += 1
                break

        return b""

    def send_udp_wait(self, data: bytes):
        """
        Send the UDP data and yields responses.

        Args:
            data (bytes): The data to send.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        if self.interface_ip:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(self.interface_ip))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)

        sock.sendto(data, (self.host, self.port))

        while True:
            try:
                data, (ip, port) = sock.recvfrom(RESPONSE_DATA_BUFF_SIZE)
            except socket.timeout:
                break

            yield data, ip, port
