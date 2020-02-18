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

from scapy.all import IP, TCP, UDP, DNS, DNSQR, sr1


logger = logging.getLogger("test")

def test_insert():
    """
    Tests the HTTP tamper 'insert' primitive.
    """
    tamper = actions.tamper.TamperAction(None, field="Host", tamper_type="insert", tamper_proto="HTTPRequest", start_index = 4, encoded_payload="%20")
    assert tamper.field == "Host", "Incorrect field."
    assert tamper.tamper_type == "insert", "Tamper action changed types."
    assert tamper.encoded_payload == "%20", "Incorrect encoded payload."
    assert tamper.decoded_payload == b" ", "Tamper failed to decode payload."
    assert str(tamper) == "tamper{HTTPRequest:Host:insert:4:%20}", "Tamper returned incorrect string representation: %s" % str(tamper)
    tamper2 = actions.tamper.TamperAction(None)
    tamper2.parse("HTTPRequest:Host:insert:4:%20", logger)
    assert str(tamper2) == str(tamper), "Tamper failed to parse correctly."

def test_replace():
    """
    Tests the HTTP tamper 'replace' primitive.
    """
    tamper = actions.tamper.TamperAction(None, field="Host", tamper_type="replace", tamper_proto="HTTPRequest", start_index = 4, encoded_payload="%20")
    assert tamper.field == "Host", "Incorrect field."
    assert tamper.tamper_type == "replace", "Tamper action changed types."
    assert tamper.encoded_payload == "%20", "Incorrect encoded payload."
    assert tamper.decoded_payload == b" ", "Tamper failed to decode payload."
    assert str(tamper) == "tamper{HTTPRequest:Host:replace:4:%20}", "Tamper returned incorrect string representation: %s" % str(tamper)
    tamper2 = actions.tamper.TamperAction(None)
    tamper2.parse("HTTPRequest:Host:replace:4:%20", logger)
    assert str(tamper2) == str(tamper), "Tamper failed to parse correctly."

def test_corrupt():
    """
    Tests the HTTP tamper 'corrupt' primitive.
    """
    tamper = actions.tamper.TamperAction(None, field="Host", tamper_type="corrupt", tamper_proto="HTTPRequest", start_index=4, end_index=6)
    assert tamper.field == "Host", "Incorrect field."
    assert tamper.tamper_type == "corrupt", "Tamper action changed types."
    assert tamper.start_index == 4, "Incorrect index."
    assert tamper.end_index == 6, "Incorrect index."
    assert str(tamper) == "tamper{HTTPRequest:Host:corrupt:4-6}", "Tamper returned incorrect string representation: %s" % str(tamper)
    tamper2 = actions.tamper.TamperAction(None)
    tamper2.parse("HTTPRequest:Host:corrupt:4-6", logger)
    assert str(tamper2) == str(tamper), "Tamper failed to parse correctly."

def test_delete():
    """
    Tests the HTTP tamper 'delete' primitive.
    """
    tamper = actions.tamper.TamperAction(None, field="Host", tamper_type="delete", tamper_proto="HTTPRequest", start_index=4, end_index=6)
    assert tamper.field == "Host", "Incorrect field."
    assert tamper.tamper_type == "delete", "Tamper action changed types."
    assert tamper.start_index == 4, "Incorrect index."
    assert tamper.end_index == 6, "Incorrect index."
    assert str(tamper) == "tamper{HTTPRequest:Host:delete:4-6}", "Tamper returned incorrect string representation: %s" % str(tamper)
    tamper2 = actions.tamper.TamperAction(None)
    tamper2.parse("HTTPRequest:Host:delete:4-6", logger)
    assert str(tamper2) == str(tamper), "Tamper failed to parse correctly."
