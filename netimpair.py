#!/usr/bin/env python

"""
The MIT License (MIT)

Copyright (c) 2015 Benjamin Xiao

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import argparse
import datetime
import os
import shlex
import signal
import subprocess
import sys
import time
import traceback


class NetemInstance(object):
    """Wrapper around netem module and tc command."""

    def __init__(self, nic, inbound, include, exclude):
        self.inbound = inbound
        self.include = include if include else ["src=0/0", "src=::/0"]
        self.exclude = exclude
        self.nic = "ifb1" if inbound else nic
        self.real_nic = nic

    @staticmethod
    def _call(command):
        """Run command."""
        subprocess.call(shlex.split(command))

    @staticmethod
    def _check_call(command):
        """Run command, raising CalledProcessError if it fails."""
        subprocess.check_call(shlex.split(command))

    @staticmethod
    def _generate_filters(filter_list):
        filter_strings = []
        filter_strings_ipv6 = []
        for tc_filter in filter_list:
            filter_tokens = tc_filter.split(",")

            filter_string = ""
            filter_string_ipv6 = ""
            try:
                for token in filter_tokens:
                    token_split = token.split("=")
                    key = token_split[0]
                    value = token_split[1]
                    # Check for ipv6 addresses and add them to the appropriate filter string
                    if key == "src" or key == "dst":
                        if "::" in value:
                            filter_string_ipv6 += f"match ip6 {key} {value} "
                        else:
                            filter_string += f"match ip {key} {value} "
                    else:
                        filter_string += f"match ip {key} {value} "
                        filter_string_ipv6 += f"match ip6 {key} {value} "
                    if key == "sport" or key == "dport":
                        filter_string += "0xffff "
                        filter_string_ipv6 += "0xffff "
            except IndexError:
                print("ERROR: Invalid filter parameters", file=sys.stderr)

            if filter_string:
                filter_strings.append(filter_string)
            if filter_string_ipv6:
                filter_strings_ipv6.append(filter_string_ipv6)

        return filter_strings, filter_strings_ipv6

    def initialize(self):
        """Set up traffic control."""
        if self.inbound:
            # Create virtual ifb device to do inbound impairment on
            self._check_call("modprobe ifb")
            self._check_call(f"ip link set dev {self.nic} up")
            # Delete ingress device before trying to add
            self._call(f"tc qdisc del dev {self.real_nic} ingress")
            # Add ingress device
            self._check_call(f"tc qdisc replace dev {self.real_nic} ingress")
            # Add filter to redirect ingress to virtual ifb device
            self._check_call(
                f"tc filter replace dev {self.real_nic} parent ffff: protocol ip prio 1 u32 match u32 0 0 flowid 1:1 action "
                f"mirred egress redirect dev {self.nic}"
            )

        # Delete network impairments from any previous runs of this script
        self._call(f"tc qdisc del root dev {self.nic}")

        # Create prio qdisc so we can redirect some traffic to be unimpaired
        self._check_call(f"tc qdisc add dev {self.nic} root handle 1: prio")

        # Apply selective impairment based on include and exclude parameters
        print("Including the following for network impairment:")
        include_filters, include_filters_ipv6 = self._generate_filters(self.include)
        for filter_string in include_filters:
            include_filter = f"tc filter add dev {self.nic} protocol ip parent 1:0 prio 3 u32 {filter_string}flowid 1:3"
            print(include_filter)
            self._check_call(include_filter)

        for filter_string_ipv6 in include_filters_ipv6:
            include_filter_ipv6 = (
                f"tc filter add dev {self.nic} protocol ipv6 parent 1:0 prio 4 u32"
                f" {filter_string_ipv6}flowid 1:3"
            )
            print(include_filter_ipv6)
            self._check_call(include_filter_ipv6)
        print()

        print("Excluding the following from network impairment:")
        exclude_filters, exclude_filters_ipv6 = self._generate_filters(self.exclude)
        for filter_string in exclude_filters:
            exclude_filter = f"tc filter add dev {self.nic} protocol ip parent 1:0 prio 1 u32 {filter_string}flowid 1:2"
            print(exclude_filter)
            self._check_call(exclude_filter)

        for filter_string_ipv6 in exclude_filters_ipv6:
            exclude_filter_ipv6 = f"tc filter add dev {self.nic} protocol ipv6 parent 1:0 prio 2 u32 {filter_string_ipv6}flowid 1:2"
            print(exclude_filter_ipv6)
            self._check_call(exclude_filter_ipv6)
        print()

    # pylint: disable=too-many-arguments
    def netem(
        self,
        loss_ratio=0,
        loss_corr=0,
        dup_ratio=0,
        delay=0,
        jitter=0,
        delay_jitter_corr=0,
        reorder_ratio=0,
        reorder_corr=0,
        toggle=None,
    ):
        """Enable packet loss."""
        if toggle is None:
            toggle = [1000000]
        self._check_call(f"tc qdisc add dev {self.nic} parent 1:3 handle 30: netem")
        while toggle:
            impair_cmd = (
                f"tc qdisc change dev {self.nic} parent 1:3 handle 30: netem loss {loss_ratio}% {loss_corr}% duplicate"
                f" {dup_ratio}% delay {delay}ms {jitter}ms {delay_jitter_corr}% reorder {reorder_ratio}% {reorder_corr}%"
            )
            print("Setting network impairment:")
            print(impair_cmd)
            # Set network impairment
            self._check_call(impair_cmd)
            print(f"Impairment timestamp: {datetime.datetime.today()}")
            time.sleep(toggle.pop(0))
            if not toggle:
                return
            self._check_call(
                f"tc qdisc change dev {self.nic} parent 1:3 handle 30: netem"
            )
            print(f"Impairment stopped timestamp: {datetime.datetime.today()}")
            time.sleep(toggle.pop(0))

    def rate(self, limit=0, buffer_length=2000, latency=20, toggle=None):
        """Enable packet reorder."""
        if toggle is None:
            toggle = [1000000]
        self._check_call(
            f"tc qdisc add dev {self.nic} parent 1:3 handle 30: tbf rate 1000mbit buffer {buffer_length} latency {latency}ms"
        )
        while toggle:
            impair_cmd = (
                f"tc qdisc change dev {self.nic} parent 1:3 handle 30: tbf rate {limit}kbit buffer {buffer_length} latency "
                f"{latency}ms"
            )
            print("Setting network impairment:")
            print(impair_cmd)
            # Set network impairment
            self._check_call(impair_cmd)
            print(f"Impairment timestamp: {datetime.datetime.today()}")
            time.sleep(toggle.pop(0))
            if not toggle:
                return
            self._check_call(
                f"tc qdisc change dev {self.nic} parent 1:3 handle 30: tbf rate 1000mbit buffer {buffer_length} latency "
                f"{latency}ms"
            )
            print(f"Impairment stopped timestamp: {datetime.datetime.today()}")
            time.sleep(toggle.pop(0))

    def teardown(self):
        """Reset traffic control rules."""
        if self.inbound:
            self._call(
                f"tc filter del dev {self.real_nic} parent ffff: protocol ip prio 1"
            )
            self._call(f"tc qdisc del dev {self.real_nic} ingress")
            self._call("ip link set dev ifb0 down")
        self._call(f"tc qdisc del root dev {self.nic}")
        print("Network impairment teardown complete.")


def init_signals(netem):
    """Catch signals in order to stop network impairment before exiting."""

    def signal_action(signum, frame):
        """To be executed upon exit signal."""
        print()
        netem.teardown()
        # Print blank line before quitting to deal with some crappy
        # terminal behavior
        print()
        exit(5)

    # Catch SIGINT and SIGTERM so that we can clean up
    for sig in [signal.SIGINT, signal.SIGTERM]:
        signal.signal(sig, signal_action)

    print(
        "Network impairment starting.",
        "Press Ctrl-C to restore normal behavior and quit.\n",
    )


def main():
    """Start application."""
    args = parse_args()

    if os.geteuid() != 0:
        print(
            "You need root permissions to enable impairment!",
            "Please run with sudo or as root.",
            file=sys.stderr,
        )
        exit(1)

    try:
        # Create NetemInstance
        netem = NetemInstance(args.nic, args.inbound, args.include, args.exclude)

        # Perform setup
        netem.initialize()

        # Catch signals
        init_signals(netem)

        # Do impairment
        if args.subparser_name == "netem":
            netem.netem(
                args.loss_ratio,
                args.loss_corr,
                args.dup_ratio,
                args.delay,
                args.jitter,
                args.delay_jitter_corr,
                args.reorder_ratio,
                args.reorder_corr,
                args.toggle,
            )
        elif args.subparser_name == "rate":
            netem.rate(args.limit, args.buffer, args.latency, args.toggle)

        # Shutdown cleanly
        netem.teardown()
    except subprocess.CalledProcessError:
        traceback.print_exc()
        netem.teardown()
        exit(5)


def parse_args():
    """Parse command-line arguments."""
    argparser = argparse.ArgumentParser(description="Network Impairment Test Tool")

    argparser.add_argument(
        "-n",
        "--nic",
        choices=os.listdir("/sys/class/net"),
        metavar="INTERFACE",
        required=True,
        help="name of the network interface to be impaired",
    )
    argparser.add_argument(
        "--inbound",
        action="store_true",
        help="do inbound impairment on the interface instead of outbound",
    )
    argparser.add_argument(
        "--include",
        action="append",
        default=[],
        help="ip addresses and/or ports to include in network "
        "impairment (example: --include src=ip,sport=portnum "
        "--include dst=ip,dport=portnum)",
    )
    argparser.add_argument(
        "--exclude",
        action="append",
        default=["dport=22", "sport=22"],
        help="ip addresses and/or ports to exclude from network "
        "impairment (example: --exclude src=ip,sport=portnum "
        "--exclude dst=ip,dport=portnum)",
    )

    subparsers = argparser.add_subparsers(
        title="impairments",
        dest="subparser_name",
        description="specify which impairment to enable",
        help="valid impairments",
    )

    # loss args
    netem_args = subparsers.add_parser("netem", help="enable packet loss")
    netem_args.add_argument(
        "--loss_ratio",
        type=int,
        default=0,
        help="specify percentage of packets that will be lost",
    )
    netem_args.add_argument(
        "--loss_corr",
        type=int,
        default=0,
        help="specify a correlation factor for the random packet loss",
    )
    # dup args
    netem_args.add_argument(
        "--dup_ratio",
        type=int,
        default=0,
        help="specify percentage of packets that will be duplicated",
    )
    # delay/jitter args
    netem_args.add_argument(
        "--delay", type=int, default=0, help="specify an overall delay for each packet"
    )
    netem_args.add_argument(
        "--jitter", type=int, default=0, help="specify amount of jitter in milliseconds"
    )
    netem_args.add_argument(
        "--delay_jitter_corr",
        type=int,
        default=0,
        help="specify a correlation factor for the random jitter",
    )
    # reorder args
    netem_args.add_argument(
        "--reorder_ratio",
        type=int,
        default=0,
        help="specify percentage of packets that will be reordered",
    )
    netem_args.add_argument(
        "--reorder_corr",
        type=int,
        default=0,
        help="specify a correlation factor for the random reordering",
    )
    # toggle parameter
    netem_args.add_argument(
        "--toggle",
        nargs="+",
        type=int,
        default=[1000000],
        help="toggles impairment on and off on specific intervals (example: "
        "--toggle 6 3 5 1 will enable impairment for 6 seconds, turn it off "
        "for 3, turn it on for 5, and turn it off for 1",
    )

    # rate limit args
    rate_args = subparsers.add_parser("rate", help="enable packet reorder")
    rate_args.add_argument(
        "--limit", type=int, default=0, help="specify rate limit in kb"
    )
    rate_args.add_argument(
        "--buffer",
        type=int,
        default=2000,
        help="specify how many tokens in terms of bytes should be available",
    )
    rate_args.add_argument(
        "--latency",
        type=int,
        default=20,
        help="specify the maximum time packets can stay in the "
        "queue before getting dropped",
    )
    rate_args.add_argument(
        "--toggle",
        nargs="+",
        type=int,
        default=[1000000],
        help="toggles impairment on and off on specific intervals (example: "
        "--toggle 6 3 5 1 will enable impairment for 6 seconds, turn it off "
        "for 3, turn it on for 5, and turn it off for 1",
    )

    return argparser.parse_args()


if __name__ == "__main__":
    main()
