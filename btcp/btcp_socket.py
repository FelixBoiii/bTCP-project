from btcp.constants import *


import struct
import logging
import random
from enum import IntEnum


logger = logging.getLogger(__name__)

class BTCPStates(IntEnum):
    """Enum class that helps you implement the bTCP state machine.

    Don't use the integer values of this enum directly. Always refer to them as
    BTCPStates.CLOSED etc.

    These states are NOT exhaustive! We left out at least one state that you
    will need to implement the bTCP state machine correctly. The intention of
    this enum is to give you some idea for states and how simple the
    transitions between them are.

    Feel free to implement your state machine in a different way, without
    using such an enum.
    """
    CLOSED      = 0
    ACCEPTING   = 1
    SYN_SENT    = 2
    SYN_RCVD    = 3
    ESTABLISHED = 4
    FIN_SENT    = 5
    CLOSING     = 6
    __          = 7 # If you need more states, extend the Enum like this.


class BTCPSignals(IntEnum):
    """Enum class that you can use to signal from the Application thread
    to the Network thread.

    For example, rather than explicitly change state in the Application thread,
    you could put one of these in a variable that the network thread reads the
    next time it ticks, and handles the state change in the network thread.
    """
    NOTHING = 0
    ACCEPT = 1
    CONNECT = 2
    SHUTDOWN = 3


class BTCPSocket:
    """Base class for bTCP client and server sockets. Contains static helper
    methods that will definitely be useful for both sending and receiving side.
    """
    def __init__(self, window, timeout, isn):
        logger.debug("__init__ called")
        self._window = window
        self._timeout_secs = timeout
        self._state = BTCPStates.CLOSED
        self._signal = BTCPSignals.NOTHING

        if isn==None:
            isn = random.randint(0,0xffff)
        self._seqnum = isn

    @property
    def timeout_secs(self):
        return self._timeout_secs

    @property
    def timeout_nanosecs(self):
        return self._timeout_secs * 1_000_000_000

    #calculates the checksum
    @staticmethod
    def in_cksum(segment):
        limit = 65536
        checksum = 0
        
        #for every two bytes it unpacks those bytes from the segment,
        #adds them to the checksum and modulus the checksum for overflow
        for step in range(0, 1018, 2):
            word = struct.unpack("!H", segment[step:step+2])[0]
            checksum += word
            if checksum >= limit:
                 checksum = checksum % limit + 1

        #creates the complement of the checksum
        checksum = ~checksum & 0xFFFF

        return checksum   

    #verifies the checksum by complementing
    @staticmethod
    def verify_checksum(segment):
        return BTCPSocket.in_cksum(segment) == 0x0000

    #builds the segment header
    @staticmethod
    def build_segment_header(seqnum, acknum, syn_set=False, ack_set=False, fin_set=False,window=0x01, length=0, checksum=0):
        
        #adds the flagbits in the exact locations in the flagbyte
        flag_byte = syn_set << 2 | ack_set << 1 | fin_set
        return struct.pack("!HHBBHH", seqnum, acknum, flag_byte, window, length, checksum)

    #unpacks the segment header
    @staticmethod
    def unpack_segment_header(header):
        seqnum, acknum, flag_byte, window, length, checksum = struct.unpack("!HHBBHH", header)
        return seqnum, acknum, flag_byte, window, length, checksum
    
    #builds the segment and sends it to lossy layer
    def create_and_send_segment(self, seqnum, acknum=0, syn_set=False, ack_set=False, fin_set=False, window=0x01, length=0, payload=b''):
        #padds the data to be exactly 1008 bytes
        if length < PAYLOAD_SIZE:
            payload = payload + b'\x00' * (PAYLOAD_SIZE - length)
        
        #creates the segment for the checksum calculation and creates the final segment
        checksum_segment = BTCPSocket.build_segment_header(seqnum, acknum, syn_set=syn_set, ack_set=ack_set, fin_set=fin_set,length=length, window= window) + payload
        checksum = BTCPSocket.in_cksum(checksum_segment)
        segment = BTCPSocket.build_segment_header(seqnum, acknum , syn_set=syn_set, ack_set=ack_set, fin_set=fin_set, checksum=checksum, length=length, window=window) + payload
            
        #sends the segment
        self._lossy_layer.send_segment(segment)
        return segment

    #increments the sequence number without overflowing
    @staticmethod
    def increment_seqnum(seqnum):
        return (seqnum + 1) % 65536
    
    #decrements the sequence number without overflowing
    @staticmethod
    def decrement_seqnum(seqnum):
        return (seqnum - 1) % 65536



# Ignore the following code;  we use this to test the bTCP project.
__suppress_nie = False

def raise_NotImplementedError(msg):
    if __suppress_nie:
        logger.warn(f"Suppressed NotImplementedError({repr(msg)})")
    else:
        raise NotImplementedError(msg)

