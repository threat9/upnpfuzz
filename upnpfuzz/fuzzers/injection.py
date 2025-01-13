import random
from typing import List


class Injection:
    """
    Fuzzer that uses command injection.
    """
    def __init__(self):
        """
        Initializes fuzzer.
        """
        self.cmd = b"reboot"

    def fuzz(self, request: List[bytes]) -> List[bytes]:
        """
        Fuzz function that adds injection to the params.

        Args:
            request (List[bytes]): The raw request params.

        Returns:
            List[bytes]: The request params with the command injection.
        """
        injection = self._get_injection(self.cmd)

        idx = random.randint(0, len(request) - 1)

        return [*request[:idx], request[idx] + injection, *request[idx + 1:]]

    def _get_injection(self, cmd: bytes) -> bytes:
        """
        Retrieve the injection bytes.

        Args:
            cmd (bytes): The command that should be used.

        Returns:
            bytes: The command enclosed with escape characters and with delimiters.
        """
        cmd = self._add_enclosures(cmd)
        cmd = self._add_delimiters(cmd)

        return cmd

    @staticmethod
    def _add_delimiters(cmd: bytes) -> bytes:
        """
        Adds delimiters to the command.

        Args:
            cmd (bytes): The command that delimiters should be added to.

        Returns:
            bytes: The command with added delimiters.
        """
        delimiters = [
            b"", b"`", b";", b"\"", b"'", b"|", b"&", b"&&", b")", b"\r", b"\n", b"%0a", b"%0d"
        ]

        for _ in range(0, random.randint(0, 3)):
            cmd = cmd + random.choice(delimiters)

        for _ in range(0, random.randint(0, 3)):
            cmd = cmd + random.choice(delimiters)

        return cmd

    @staticmethod
    def _add_enclosures(cmd: bytes) -> bytes:
        """
        Adds enclosures to the command.

        Args:
            cmd (bytes): Command that should be injected.

        Returns:
            bytes: The command that is enclosed with escape characters.
        """
        enclosures = [
            (b"", b""),
            (b"`", b"`"),
            (b"$(", b")"),
            (b";", b";"),
            (b"|", b""),
        ]

        left, right = random.choice(enclosures)
        return left + cmd + right
