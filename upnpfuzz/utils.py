import subprocess
from typing import Tuple
from urllib.parse import urlparse


def parse_url(url: str) -> Tuple[str, str, int]:
    """
    Parses provided URL to retrieve base url, host and port.

    Args:
        url (str): The URL to parse.

    Returns:
        Tuple[str, str, int]: The base url, host address and the port number.
    """
    parsed_url = urlparse(url)
    base_url = parsed_url.scheme + "://" + parsed_url.netloc
    host, port = parsed_url.netloc.split(":")
    return base_url, host, int(port)


def run_command(cmd: str, inp: bytes = b"") -> Tuple[bytes, bytes]:
    """
    Executes command and returns the output.

    Args:
        cmd (str): The command to execute.
        inp (bytes): The input data that is sent via stdin.

    Returns:
        Tuple[bytes, bytes]: The output from stdout and sterr.
    """
    cmd = cmd.split(" ")
    process = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    if inp:
        out, err = process.communicate(inp)
    else:
        out, err = process.communicate()

    return out, err
