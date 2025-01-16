import argparse
import signal

from upnpfuzz.display import print_error, print_line
from upnpfuzz.protocols.base import Strategy
from upnpfuzz.protocols.esp import ESP
from upnpfuzz.protocols.soap import SOAP
from upnpfuzz.protocols.ssdp import SSDP


def signal_handler(sig, frame):
    print_line("exiting...")
    exit(0)


def main():
    signal.signal(signal.SIGINT, signal_handler)

    parser = argparse.ArgumentParser(prog="upnpfuzz")
    parser.add_argument("--discover", action="store_true")

    parser.add_argument("--ssdp", type=str)
    parser.add_argument("--soap", type=str)
    parser.add_argument("--esp", type=str)

    parser.add_argument("--list", action="store_true")
    parser.add_argument("--raw", action="store_true")
    parser.add_argument("--fuzz", action="store_true")
    parser.add_argument("--injection", action="store_true")
    parser.add_argument("--overflow", action="store_true")
    parser.add_argument("--radamsa", action="store_true")
    parser.add_argument("--delay", type=float, default=0)

    parser.add_argument("--alive-url", type=str, default="")
    parser.add_argument("--crash-dir", type=str, default="/tmp/fuzz_upnpfuzz")
    parser.add_argument("--restart-cmd", type=str, default="")
    parser.add_argument("--restart-delay", type=int, default=30)

    parser.add_argument("--radamsa-path", type=str, default="")
    parser.add_argument("--network-timeout", type=float, default=5)
    parser.add_argument("--interface-ip", type=str)

    parser.add_argument("--esp-callback", type=str, default="http://192.168.2.159:8000/callback")

    args = parser.parse_args()

    if args.discover:
        ssdp = SSDP("239.255.255.250:1900", network_timeout=args.network_timeout, interface_ip=args.interface_ip)
        ssdp.discover()

    strategy = None
    if args.fuzz:
        strategy = Strategy.ALL
    elif args.injection:
        strategy = Strategy.INJECTION
    elif args.overflow:
        strategy = Strategy.OVERFLOW
    elif args.radamsa:
        strategy = Strategy.RADAMSA

    if args.ssdp:
        ssdp = SSDP(args.ssdp, args.delay, args.alive_url, args.crash_dir, args.restart_cmd, args.restart_delay, args.radamsa_path, args.network_timeout, interface_ip=args.interface_ip)
        if args.raw:
            ssdp.raw()
        elif strategy:
            ssdp.fuzz(strategy)

    elif args.soap:
        soap = SOAP(args.soap, args.delay, args.alive_url, args.crash_dir, args.restart_cmd, args.restart_delay, args.radamsa_path, args.network_timeout)
        if not soap.generator.generate_grammar():
            print_error("failed to retrieve actions and build grammar")
            return

        if args.list:
            soap.list()
        elif args.raw:
            soap.raw()
        elif strategy:
            soap.fuzz(strategy)

    elif args.esp:
        esp = ESP(args.esp, args.delay, args.alive_url, args.crash_dir, args.restart_cmd, args.restart_delay, args.radamsa_path, args.network_timeout, args.esp_callback)
        if not esp.generator.generate_grammar():
            print_error("failed to retrieve events and build grammar")
            return

        if args.raw:
            esp.raw()
        elif strategy:
            esp.fuzz(strategy)


if __name__ == "__main__":
    main()
