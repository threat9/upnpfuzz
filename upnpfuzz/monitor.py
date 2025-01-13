import datetime
import time

import requests

from upnpfuzz.display import print_status, print_success
from upnpfuzz.utils import run_command


class Monitor:
    """
    Handles monitoring of the target and saving request in case of detecting crash.
    """
    def __init__(self, alive_url: str, crash_dir: str, restart_cmd: str, restart_delay: float):
        """
        Initializes the Monitor .

        Args:
            alive_url (str): The url that should be requested after sending every fuzzed request.
            crash_dir (str): The directory where the crashes should be saved.
            restart_cmd (str): The command that should be executed after the target crashed.
            restart_delay (float): The amount of time to wait until re-checking liveness of the target.
        """
        self.alive_url = alive_url
        self.crash_dir = crash_dir
        self.crashes = 0
        self.restart_cmd = restart_cmd
        self.restart_delay = restart_delay

    def check_alive(self) -> bool:
        """
        Checks if the target is alive.

        Returns:
            bool - Returns true if the target is alive or False if the target is not alive.
        """
        if not self.alive_url:
            return True

        try:
            requests.get(self.alive_url)
            return True
        except requests.exceptions.RequestException:
            print_status(f"The target at alive url ({self.alive_url}) does not respond")

        return False

    def save_crash(self, request: bytes) -> None:
        """
        Saves the request in the crash file.

        Args:
            request (bytes): The request that should be saved.
        """
        self.crashes += 1
        current_time = datetime.datetime.now()
        filename = f"crash_{self.crashes}_{current_time}"
        path = f"{self.crash_dir}/{filename}"
        print_success(f"Saving crash to {path}")
        with open(path, "wb+") as f:
            f.write(request)

    def handle_crash(self, request: bytes) -> None:
        """
        Handles crash by saving it and restarting target.

        Args:
            request (bytes): The request that should be saved.
        """
        self.save_crash(request)

        if self.restart_cmd:
            run_command(self.restart_cmd)

        while not self.check_alive():
            time.sleep(self.restart_delay)
