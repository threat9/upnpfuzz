import random

from upnpfuzz.generators.soap import SOAPGenerator
from upnpfuzz.network import Network, NetworkProtocol
from upnpfuzz.protocols.base import BaseProtocol, FuzzResponse, Strategy
from upnpfuzz.utils import parse_url


class SOAP(BaseProtocol):
    def __init__(
            self,
            target: str,
            delay: float = 0,
            alive_url: str = "",
            crash_dir: str = "",
            restart_cmd: str = "",
            restart_delay: float = 10,
            radamsa_path: str = "",
            network_timeout: float = 5
    ):
        """
        Initializes the SOAP instance.

        Args:
            target (str): The target address.
            delay (float): The amount of seconds to wait between sending every request.
            alive_url (str): The address that should be checked after sending every request to check the liveness.
            crash_dir (str): The directory where the crashes should be saved.
            restart_cmd (str): The command that should be executed to restart the target device.
            restart_delay (float): The amount of seconds to wait after restarting the target.
            radamsa_path (str): The custom path to radamsa binary fuzzer.
            network_timeout (float): The amount of seconds to wait before the connection times out.
        """

        base_url, host, port = parse_url(target)

        network = Network(host, port, NetworkProtocol.TCP, network_timeout)
        generator = SOAPGenerator(target)
        super().__init__(network, generator, delay, alive_url, crash_dir, restart_cmd, restart_delay, radamsa_path)

    def list(self) -> None:
        """
        Lists and prints all actions offered by the target.
        """
        self.generator.list()

    def fuzz_radamsa(self) -> FuzzResponse:
        """
        Generates the request and fuzzes it using radamsa fuzzer.

        Returns:
            FuzzResponse: The fuzz response that includes the used strategy and the fuzzed request.
        """
        req = self.generator.get_request()
        body_params = req.get_body_params()
        request_body = req.finalize_body(body_params)

        if body_params and random.choice([True, False]):
            request_body = self.radamsa.fuzz(request_body)
            headers_params = req.get_headers_params(len(request_body))
            request_headers = req.finalize_headers(headers_params)
        else:
            headers_params = req.get_headers_params(len(request_body))
            request_headers = req.finalize_headers(headers_params)
            request_headers = self.radamsa.fuzz(request_headers)

        request = request_headers + request_body
        return Strategy.RADAMSA, request

    def fuzz_injection(self) -> FuzzResponse:
        """
        Generates the request and fuzzes it using injection fuzzer.

        Returns:
            FuzzResponse: The fuzz response that includes the used strategy and the fuzzed request.
        """
        req = self.generator.get_request()
        body_params = req.get_body_params()

        if body_params and random.choice([True, False]):
            body_params = self.injection.fuzz(body_params)
            request_body = req.finalize_body(body_params)
            headers_params = req.get_headers_params(len(request_body))
        else:
            request_body = req.finalize_body(body_params)
            headers_params = req.get_headers_params(len(request_body))
            headers_params = self.injection.fuzz(headers_params)

        request_headers = req.finalize_headers(headers_params)
        request = request_headers + request_body
        return Strategy.INJECTION, request

    def fuzz_overflow(self) -> FuzzResponse:
        """
        Generates the request and fuzzes it using overflow fuzzer.

        Returns:
            FuzzResponse: The fuzz response that includes the used strategy and the fuzzed request.
        """
        req = self.generator.get_request()
        body_params = req.get_body_params()

        if body_params and random.choice([True, False]):
            body_params = self.overflow.fuzz(body_params)
            request_body = req.finalize_body(body_params)
            headers_params = req.get_headers_params(len(request_body))
        else:
            request_body = req.finalize_body(body_params)
            headers_params = req.get_headers_params(len(request_body))
            headers_params = self.overflow.fuzz(headers_params)

        request_headers = req.finalize_headers(headers_params)
        request = request_headers + request_body

        return Strategy.OVERFLOW, request

    def fuzz_raw(self) -> FuzzResponse:
        """
        Generates random raw requests without fuzzing them.

        Returns:
            FuzzResponse: The fuzz response that includes the used strategy and the raw request.
        """
        req = self.generator.get_request()
        body_params = req.get_body_params()
        request_body = req.finalize_body(body_params)

        headers_params = req.get_headers_params(len(request_body))
        request_headers = req.finalize_headers(headers_params)

        request = request_headers + request_body

        return Strategy.RAW, request
