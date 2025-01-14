import datetime
import math
import os

from upnpfuzz._version import version
from upnpfuzz.network import NetworkStats

TERM_CLEAR = b"\x1b[H\x1b[2J"

CGRAY = "\033[1;30m"
CYELLOW = "\033[1;33m"
CWHITE = "\033[1;60m"
CCLEAR = "\033[0m"
CBLUE = "\033[1;36m"

TLC = b"\xda"
BLC = b"\xc0"
HL = b"\xc4"
HXD = b"\xc2"
VL = b"\xb3"
VXL = b"\xc3"
VXR = b"\xb4"
VXU = b"\xc1"
VXH = b"\xc5"
RTC = b"\xbf"
RBC = b"\xd9"

MAX_WIDTH = 50
MAX_REQUEST_RESPONSE_SIZE = 2048


def print_line(*args, **kwargs):
    """
    Prints line.
    """
    print(*args, **kwargs)


def print_status(*args, **kwargs):
    """
    Prints status with a correct prefix.
    """
    print("\033[94m[*]\033[0m", *args, **kwargs)


def print_success(*args, **kwargs):
    """
    Prints success with a correct prefix.
    """
    print("\033[92m[+]\033[0m", *args, **kwargs)


def print_error(*args, **kwargs):
    """
    Prints error with a correct prefix.
    """
    print("\033[91m[-]\033[0m", *args, **kwargs)


def get_length_no_colors(text: bytes) -> int:
    """
    Calculates the length of text by ignoring colors bytes.

    Args:
        text (bytes): The text that the length should be calculated for.

    Returns:
        int: The length of the text.
    """
    length = 0
    in_escape = False

    for char in text:
        if in_escape:
            if char in b"m":
                in_escape = False
        elif char == 0x1b:
            in_escape = True
        else:
            length += 1

    return length


class Display:
    """
    Handles display of fuzzing process.
    """
    def __init__(self):
        """
        Initializes display.
        """
        self.width = MAX_WIDTH

    def print_banner(self) -> None:
        """
        Prints banner.
        """
        headline = f"{CYELLOW}upnpfuzz (v{version}) by threat9{CCLEAR}".encode("utf-8")
        headline = b" " * (self.width - int(get_length_no_colors(headline) / 2)) + headline
        print_line(headline.decode("utf-8"))

    def print_stats(
            self,
            network_stats: NetworkStats,
            crashes: int,
            generator,
            selected_strategy,
            current_strategy
    ) -> None:
        """
        Prints stats during fuzzing.

        Args:
            network_stats (NetworkStats): The dataclass that holds network stats.
            crashes (int): The number of detected crashes.
            generator: The generator that creates target protocol requests.
            selected_strategy (Strategy): The strategy that was selected by the user.
            current_strategy (Strategy): The current strategy used for fuzzing.
        """
        width, _ = os.get_terminal_size()

        if width >= MAX_WIDTH * 2:
            width = MAX_WIDTH
        else:
            width = int(width / 2) - 1

        self.width = width

        current_time = datetime.datetime.now()
        time_since = current_time - network_stats.start_time

        total_seconds = int(time_since.total_seconds())
        hours, remainder = divmod(total_seconds, 3600)
        minutes, seconds = divmod(remainder, 60)

        if time_since.seconds > 0:
            speed = math.ceil(network_stats.total_requests / time_since.seconds)
        else:
            speed = 0

        print_line(TERM_CLEAR.decode("utf-8"))
        self.print_banner()

        first_headline_left = TLC + HL * 2 + f" {CBLUE}process timing{CCLEAR} ".encode("utf-8")
        first_headline_left += HL * (self.width - get_length_no_colors(first_headline_left))
        second_headline_left = VXL + HL * 2 + f" {CBLUE}fuzzing{CCLEAR} ".encode("utf-8")
        second_headline_left += HL * (self.width - get_length_no_colors(second_headline_left))
        left = [
            first_headline_left,
            VL + f"   start time : {CWHITE}{network_stats.start_time.strftime('%Y-%m-%d %H:%M:%S')}{CCLEAR}".encode("utf-8"),
            VL + f" current time : {CWHITE}{current_time.strftime('%Y-%m-%d %H:%M:%S')}{CCLEAR}".encode("utf-8"),
            VL + f"  running for : {CWHITE}{hours}h, {minutes}m, {seconds}s{CCLEAR}".encode("utf-8"),

            second_headline_left,
            VL + f" strategy : {CWHITE}{current_strategy.value}{CCLEAR}".encode("utf-8"),
            VL + f"    speed : {CWHITE}{speed}/s{CCLEAR}".encode("utf-8"),
            VL + f"  crashes : {CWHITE}{crashes}{CCLEAR}".encode("utf-8"),

            BLC + HL * (self.width - 1)
        ]

        first_headline_right = HXD + HL * 2 + f" {CBLUE}configuration{CCLEAR} ".encode("utf-8")
        first_headline_right += HL * (self.width - get_length_no_colors(first_headline_right)) + RTC
        second_headline_right = VXH + HL * 2 + f" {CBLUE}network{CCLEAR} ".encode("utf-8")
        second_headline_right += HL * (self.width - get_length_no_colors(second_headline_right)) + VXR
        right = [
            first_headline_right,
            VL + f" protocol : {CWHITE}{generator}{CCLEAR}".encode("utf-8"),
            VL + f" strategy : {CWHITE}{selected_strategy.value}{CCLEAR}".encode("utf-8"),
            VL,

            second_headline_right,
            VL + f" requests : {CWHITE}{network_stats.total_requests}{CCLEAR}".encode("utf-8"),
            VL + f" timeouts : {CWHITE}{network_stats.timeouts}{CCLEAR}".encode("utf-8"),
            VL + f"   errors : {CWHITE}{network_stats.errors}{CCLEAR}".encode("utf-8"),

            VXU + HL * (self.width - 1) + RBC
        ]

        for i in range(0, len(left)):
            left_side = left[i] + b" " * (self.width - get_length_no_colors(left[i]))
            if len(right[i]) > 1:
                right_side = right[i] + b" " * (self.width - get_length_no_colors(right[i]))
            else:
                right_side = right[i] + b" " * (self.width - 1)

            if len(right[i]) < self.width:
                right_side += VL
            print_line((left_side + right_side).decode("cp437"))

    def print_request(self, request: bytes) -> None:
        """
        Prints request.

        Args:
            request (bytes): Request that should be displayed.
        """
        headline = b" request "
        length = self.width - int(len(headline) / 2)
        headline = HL * length + headline + HL * length

        print_line(headline.decode("cp437"))
        try:
            print_line(request.decode("utf-8")[:MAX_REQUEST_RESPONSE_SIZE])
        except Exception:
            print_line(str(request[:MAX_REQUEST_RESPONSE_SIZE]))

    def print_response(self, response: bytes):
        """
        Prints response.

        Args:
            response (bytes): Response that should be displayed.
        """
        headline = b" response "
        length = self.width - int(len(headline) / 2)
        headline = HL * length + headline + HL * length

        print_line(headline.decode("cp437"))
        try:
            print_line(response.decode("utf-8")[:MAX_REQUEST_RESPONSE_SIZE])
        except Exception:
            print_line(str(response[:MAX_REQUEST_RESPONSE_SIZE]))
