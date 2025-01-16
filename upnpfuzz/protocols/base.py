import abc
import enum
import random
import time
from typing import Callable, Tuple, TypeAlias

from upnpfuzz.display import Display
from upnpfuzz.fuzzers.injection import Injection
from upnpfuzz.fuzzers.overflow import Overflow
from upnpfuzz.fuzzers.radamsa import Radamsa
from upnpfuzz.monitor import Monitor
from upnpfuzz.network import Network


class Strategy(enum.Enum):
    """
    Represents the possible fuzzing strategies.
    """
    RAW = "raw"
    ALL = "all"
    RADAMSA = "radamsa"
    INJECTION = "injection"
    OVERFLOW = "overflow"


FuzzResponse: TypeAlias = Tuple[Strategy, bytes]


class BaseProtocol:
    """
    The base class that the fuzzed protocol SSDP/SOAP/ESP has to inherit from.
    """
    __metaclass__ = abc.ABCMeta

    def __init__(
            self,
            network: Network,
            generator,
            delay: float,
            alive_url: str,
            crash_dir: str,
            restart_cmd: str,
            restart_delay: float,
            radamsa_path: str,
    ):
        """
        Initializes the base instance.

        Args:
            network (Network): The network
            generator: The generator used for generating raw requests.
            delay (float): The amount of seconds to wait between sending every request.
            alive_url (str): The address that should be checked after sending every request to check the liveness.
            crash_dir (str): The directory where the crashes should be saved.
            restart_cmd (str): The command that should be executed to restart the target device.
            restart_delay (float): The amount of seconds to wait after restarting the target.
            radamsa_path (str): The custom path to radamsa binary fuzzer.
        """

        self.generator = generator
        self.network = network
        self.monitor = Monitor(alive_url, crash_dir, restart_cmd, restart_delay)

        self.display = Display()
        self.display.print_banner()

        self.delay = delay

        self.radamsa = Radamsa(radamsa_path)
        self.injection = Injection()
        self.overflow = Overflow()

    def raw(self) -> None:
        """
        The entry point for sending raw requests.
        """
        self.monitor.create_crash_dir()

        fuzzer = self.fuzz_raw
        self.run(fuzzer, Strategy.RAW)

    def fuzz(self, strategy: Strategy) -> None:
        """
        The entrypoint for fuzzing.
        """
        self.monitor.create_crash_dir()

        fuzzer = self.fuzz_all

        if strategy == Strategy.RADAMSA:
            fuzzer = self.fuzz_radamsa
        elif strategy == Strategy.INJECTION:
            fuzzer = self.fuzz_injection
        elif strategy == Strategy.OVERFLOW:
            fuzzer = self.fuzz_overflow

        self.run(fuzzer, strategy)

    def fuzz_all(self) -> FuzzResponse:
        """
        Fuzzes the target by randomly selecting strategy.

        Returns:
            FuzzResponse: The fuzz response that includes the used strategy and the fuzzed request.
        """
        fuzzer = random.choice([
            self.fuzz_radamsa,
            self.fuzz_injection,
            self.fuzz_overflow
        ])

        return fuzzer()

    def run(self, fuzzer: Callable[[], FuzzResponse], selected_strategy: Strategy) -> None:
        """
        Runs the fuzzing loop.

        Args:
            fuzzer (Callable[[], FuzzResponse]): The fuzzer function that should be executed: radamsa/injection/overflow.
            selected_strategy (Strategy): The strategy that was selected.
        """
        while True:
            current_strategy, request = fuzzer()

            self.display.print_stats(
                self.network.stats,
                self.monitor.crashes,
                self.generator.name,
                selected_strategy,
                current_strategy
            )
            self.display.print_request(request)

            response = self.network.send(request)
            self.display.print_response(response)

            if not self.monitor.check_alive():
                self.monitor.handle_crash(self.generator.name, current_strategy, request)

            time.sleep(self.delay)

    @abc.abstractmethod
    def fuzz_radamsa(self) -> FuzzResponse:
        """
        Generates the request and fuzzes it using radamsa fuzzer.

        Returns:
            FuzzResponse: The fuzz response that includes the used strategy and the fuzzed request.
        """
        pass

    @abc.abstractmethod
    def fuzz_injection(self) -> FuzzResponse:
        """
        Generates the request and fuzzes it using injection fuzzer.

        Returns:
            FuzzResponse: The fuzz response that includes the used strategy and the fuzzed request.
        """
        pass

    @abc.abstractmethod
    def fuzz_overflow(self) -> FuzzResponse:
        """
        Generates the request and fuzzes it using overflow fuzzer.

        Returns:
            FuzzResponse: The fuzz response that includes the used strategy and the fuzzed request.
        """
        pass

    @abc.abstractmethod
    def fuzz_raw(self) -> FuzzResponse:
        """
        Generates random raw requests without fuzzing them.

        Returns:
            FuzzResponse: The fuzz response that includes the used strategy and the raw request.
        """
        pass
