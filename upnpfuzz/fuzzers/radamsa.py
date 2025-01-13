import shutil

from upnpfuzz.display import print_error
from upnpfuzz.utils import run_command


class Radamsa:
    """
    Fuzzer that uses Radamsa for fuzzing.
    """

    binary = "radamsa"

    def __init__(self, radamsa_path: str):
        """
        Initializes Radamsa fuzzer.

        Args:
            radamsa_path (str): The path to the radamsa binary.
        """
        if radamsa_path:
            self.binary = radamsa_path

        if shutil.which(radamsa_path) is None:
            print_error("radamsa is not installed")

    def fuzz(self, request: bytes) -> bytes:
        """
        Fuzzes the request with Radamsa.

        Args:
            request (bytes): The raw request to fuzz.

        Returns:
            bytes: Fuzzed request with Radamsa.
        """
        out, err = run_command(
            cmd=self.binary,
            inp=request
        )

        return out
