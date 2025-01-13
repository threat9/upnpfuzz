from upnpfuzz.generators.esp import ESPGenerator
from upnpfuzz.network import Network, NetworkProtocol
from upnpfuzz.protocols.base import BaseProtocol, FuzzResponse, Strategy
from upnpfuzz.utils import parse_url


class ESP(BaseProtocol):
    def __init__(
            self,
            target: str,
            delay: float = 0,
            alive_url: str = "",
            crash_dir: str = "",
            restart_cmd: str = "",
            restart_delay: str = 10,
            radamsa_path: str = "",
            network_timeout = 5,
    ):
        """
        Initializes the ESP instance.

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
        generator = ESPGenerator(target)
        super().__init__(network, generator, delay, alive_url, crash_dir, restart_cmd, restart_delay, radamsa_path)

    def fuzz_radamsa(self) -> FuzzResponse:
        """
        Generates the request and fuzzes it using radamsa fuzzer.

        Returns:
            FuzzResponse: The fuzz response that includes the used strategy and the fuzzed request.
        """
        req = self.generator.get_request()
        headers_params = req.get_headers_params()
        request_headers = req.finalize_headers(headers_params)
        request_headers = self.radamsa.fuzz(request_headers)

        return Strategy.RADAMSA, request_headers

    def fuzz_injection(self) -> FuzzResponse:
        """
        Generates the request and fuzzes it using injection fuzzer.

        Returns:
            FuzzResponse: The fuzz response that includes the used strategy and the fuzzed request.
        """
        req = self.generator.get_request()
        headers_params = req.get_headers_params()
        headers_params = self.injection.fuzz(headers_params)
        request_headers = req.finalize_headers(headers_params)

        return Strategy.INJECTION, request_headers

    def fuzz_overflow(self) -> FuzzResponse:
        """
        Generates the request and fuzzes it using overflow fuzzer.

        Returns:
            FuzzResponse: The fuzz response that includes the used strategy and the fuzzed request.
        """
        req = self.generator.get_request()
        headers_params = req.get_headers_params()
        headers_params = self.overflow.fuzz(headers_params)
        request_headers = req.finalize_headers(headers_params)

        return Strategy.OVERFLOW, request_headers

    def fuzz_raw(self) -> FuzzResponse:
        """
        Generates random raw requests without fuzzing them.

        Returns:
            FuzzResponse: The fuzz response that includes the used strategy and the raw request.
        """
        req = self.generator.get_request()
        headers_params = req.get_headers_params()
        request_headers = req.finalize_headers(headers_params)

        return Strategy.RAW, request_headers
