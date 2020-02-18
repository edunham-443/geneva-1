import copy
import logging
import sys
import pytest
import random
# Include the root of the project
sys.path.append("..")

import actions.strategy
import actions.packet
import actions.utils
import actions.tamper
import actions.layer

from scapy.all import IP, TCP, UDP, DNS, DNSQR, sr1, Raw, send  
from scapy.layers.http import *
from test_tamper import confirm_unchanged

#from actions.http import HTTPRequest, HTTP

logger = logging.getLogger("test")

def test_insert():
    """
    Tests the HTTP tamper 'insert' primitive.
    Ensure the space is added at character 4.
    """
    strat1 = actions.utils.parse("[TCP:flags:PA]-tamper{HTTPRequest:Host:insert:4:%20}-| \/", logger)
    p1 = IP(src="127.0.0.1", dst="127.0.0.1")/ \
        TCP(sport=2222, dport=3333, seq=100, ack=100, flags="PA")/ \
            HTTP()/ \
                HTTPRequest(b"POST /index.html?q=ultrasurf HTTP/1.1\r\nHost: google.com\r\n\r\n")
    
    parsed_packet = actions.packet.Packet(p1)
    packets = strat1.act_on_packet(parsed_packet, logger, direction="out")
    assert packets, "Strategy dropped PA packets"
    assert len(packets) == 1
    assert packets[0]["TCP"].flags == "PA"
    assert packets[0]["HTTPRequest"].fields["Host"] == b"Host : google.com"

def test_insert_many():
    """
    Tests the HTTP tamper 'insert' primitive.
    Ensure the space is added at character 4.
    """
    strat1 = actions.utils.parse("[TCP:flags:PA]-tamper{HTTPRequest:Host:insert:4:%20123aaa%20%203}-| \/", logger)
    p1 = IP(src="127.0.0.1", dst="127.0.0.1")/ \
        TCP(sport=2222, dport=3333, seq=100, ack=100, flags="PA")/ \
            HTTP()/ \
                HTTPRequest(b"POST /index.html?q=ultrasurf HTTP/1.1\r\nHost: google.com\r\n\r\n")
    
    parsed_packet = actions.packet.Packet(p1)
    packets = strat1.act_on_packet(parsed_packet, logger, direction="out")
    assert packets, "Strategy dropped PA packets"
    assert len(packets) == 1
    assert packets[0]["TCP"].flags == "PA"
    assert packets[0]["HTTPRequest"].fields["Host"] == b"Host 123aaa  3: google.com"

def test_insert_direct():
    """
    Tests the HTTP tamper "insert" primitive.
    Ensure it works being directly called.
    """
    p1 = IP(src="127.0.0.1", dst="127.0.0.1")/ \
        TCP(sport=2222, dport=3333, seq=100, ack=100, flags="PA")/ \
            HTTP()/ \
                HTTPRequest(b"POST /index.html?q=ultrasurf HTTP/1.1\r\nHost: google.com\r\n\r\n")
    parsed_packet = actions.packet.Packet(p1)

    tamperAction = actions.tamper.TamperAction(None, tamper_proto="HTTPRequest", field="Host", tamper_type="insert", start_index=4, encoded_payload="%20")
    assert str(tamperAction) == "tamper{HTTPRequest:Host:insert:4:%20}", "Tamper returned incorrect string representation: %s" % str(tamperAction)
    original = copy.deepcopy(p1)
    tamperAction.tamper(parsed_packet, logger)

    # Confirm tamper didn't corrupt anything else in the TCP header
    #assert confirm_unchanged(parsed_packet, original, TCP, []) #TODO we gotta fix

    # Confirm tamper didn't corrupt anything else in the IP header
    #assert confirm_unchanged(parsed_packet, original, IP, [])
    assert p1["TCP"].sport == 2222
    assert p1["HTTPRequest"].fields["Host"] == b"Host : google.com"

def test_replace():
    """
    Tests the HTTP tamper 'replace' primitive.
    Replace the fourth character of the Host with a space.
    """
    strat1 = actions.utils.parse("[TCP:flags:PA]-tamper{HTTPRequest:Host:replace:4:%20} \/", logger)
    p1 = IP(src="127.0.0.1", dst="127.0.0.1")/ \
        TCP(sport=2222, dport=3333, seq=100, ack=100, flags="PA")/ \
            HTTP()/ \
                HTTPRequest(b"POST /index.html?q=ultrasurf HTTP/1.1\r\nHost: google.com\r\n\r\n")
    
    parsed_packet = actions.packet.Packet(p1)
    packets = strat1.act_on_packet(parsed_packet, logger, direction="out")
    assert packets, "Strategy dropped PA packets"
    assert len(packets) == 1
    assert packets[0]["TCP"].flags == "PA"
    assert packets[0]["HTTPRequest"].fields["Host"] == b"Host  google.com"

def test_corrupt():
    """
    Tests the HTTP tamper 'corrupt' primitive.
    Make sure that corrupt changes the packet to something else.
    """
    
    strat1 = actions.utils.parse("[TCP:flags:PA]-tamper{HTTPRequest:Host:corrupt:4-5} \/", logger)
    p1 = IP(src="127.0.0.1", dst="127.0.0.1")/ \
        TCP(sport=2222, dport=3333, seq=100, ack=100, flags="PA")/ \
            HTTP()/ \
                HTTPRequest(b"POST /index.html?q=ultrasurf HTTP/1.1\r\nHost: google.com\r\n\r\n")
    
    parsed_packet = actions.packet.Packet(p1)
    packets = strat1.act_on_packet(parsed_packet, logger, direction="out")
    assert packets, "Strategy dropped PA packets"
    assert len(packets) == 1
    assert packets[0]["TCP"].flags == "PA"
    print(packets[0]["HTTPRequest"].fields["Host"])
    print(packets[0].show2())
    assert packets[0]["HTTPRequest"].fields["Host"][4] != b":"
    assert packets[0]["HTTPRequest"].fields["Host"][5] != b" "
    # When python gets a single byte value, it gets the int value
    assert packets[0]["HTTPRequest"].fields["Host"][3] == 116 
    assert packets[0]["HTTPRequest"].fields["Host"][6] == 103

    #TODO: Support
    return
    
def test_delete():
    """
    Tests the HTTP tamper 'delete' primitive.
    Delete characters 4-6 of the Host parameter.
    """
    strat1 = actions.utils.parse("[TCP:flags:PA]-tamper{HTTPRequest:Host:delete:4-6} \/", logger)
    p1 = IP(src="127.0.0.1", dst="127.0.0.1")/ \
        TCP(sport=2222, dport=3333, seq=100, ack=100, flags="PA")/ \
            HTTP()/ \
                HTTPRequest(b"POST /index.html?q=ultrasurf HTTP/1.1\r\nHost: google.com\r\n\r\n")
    
    parsed_packet = actions.packet.Packet(p1)
    packets = strat1.act_on_packet(parsed_packet, logger, direction="out")
    assert packets, "Strategy dropped PA packets"
    assert len(packets) == 1
    assert packets[0]["TCP"].flags == "PA"
    assert packets[0]["HTTPRequest"].fields["Host"] == b"Hostoogle.com"