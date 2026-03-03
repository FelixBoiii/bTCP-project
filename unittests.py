#!/usr/bin/env python3
#
# Some unit tests to help you hone aspects your BTCP implementation.
#
# The unit tests are roughly ordered by difficulty indicated by a number 00-99.
# Getting all tests working up to difficulty 50 is considered decent.
#
# We'll be adding more test during the course of the semester, so please keep an eye
# on Brightspace.

import unittest
import multiprocessing
import logging
import btcp.server_socket
import btcp.client_socket
import btcp.btcp_socket
import queue
import contextlib
import threading
import select
import string
import struct
import time
import queue
import sys
import os

DEFAULT_WINDOW = 10 
DEFAULT_TIMEOUT = 2 # seconds
DEFAULT_LOGLEVEL = 'WARNING'

logger = logging.getLogger(os.path.basename(__file__)) # we don't want __main__

class T(unittest.TestCase):
    def test_00_segment_length(self): 
        # this tests checks that segments have the correct size - 1018 bytes
        barrier = multiprocessing.Barrier(2)
        run_in_separate_processes((barrier,), 
                                  T._segment_length_client, 
                                  T._segment_length_server)
    @staticmethod
    def _segment_length_client(barrier):
        c = btcp.client_socket.BTCPClientSocket(DEFAULT_WINDOW, DEFAULT_TIMEOUT)
        with c._lossy_layer.effect(SegmentLenChecker):
            c.connect()
            c.send(b"Hello world!")
            c.shutdown()
            barrier.wait()

    @staticmethod
    def _segment_length_server(barrier):
        s = btcp.server_socket.BTCPServerSocket(DEFAULT_WINDOW, DEFAULT_TIMEOUT)
        s.accept()
        while s.recv() != b'':
            pass
        barrier.wait()


    def test_10_connect(self): 
        barrier = multiprocessing.Barrier(2)
        run_in_separate_processes((barrier,), 
                                  T._connect_client, 
                                  T._connect_server)
    @staticmethod
    def _connect_client(barrier):
        c = btcp.client_socket.BTCPClientSocket(DEFAULT_WINDOW, DEFAULT_TIMEOUT)
        c.connect()
        barrier.wait()

    @staticmethod
    def _connect_server(barrier):
        s = btcp.server_socket.BTCPServerSocket(DEFAULT_WINDOW, DEFAULT_TIMEOUT)
        s.accept()
        barrier.wait()

    def test_11_hello_world(self): 
        barrier = multiprocessing.Barrier(2)
        run_in_separate_processes((barrier,), 
                                  T._hello_world_client, 
                                  T._hello_world_server)
    @staticmethod
    def _hello_world_client(barrier):
        c = btcp.client_socket.BTCPClientSocket(DEFAULT_WINDOW, DEFAULT_TIMEOUT)
        c.connect()
        c.send(b"Hello world!")
        barrier.wait()

    @staticmethod
    def _hello_world_server(barrier):
        s = btcp.server_socket.BTCPServerSocket(DEFAULT_WINDOW, DEFAULT_TIMEOUT)
        s.accept()
        rh = RecvHelper(s)
        rh.expect(b"Hello world!")
        barrier.wait()


    def test_15_old_segments(self): 
        # this tests replays some messages from a previous connection,
        # which should only cause you trouble when you don't use random initial sequence numbers
        barrier = multiprocessing.Barrier(2)
        run_in_separate_processes((barrier,), 
                                  T._old_segments_client, 
                                  T._old_segments_server, timeout=10)
   
    @staticmethod
    def _old_segments_client(barrier):
        c = btcp.client_socket.BTCPClientSocket(DEFAULT_WINDOW, DEFAULT_TIMEOUT)
        c.connect()
        with c._lossy_layer.effect(Record) as recorder:
            c.send(b"Hello world!")
            c.shutdown()
            c.close()
            barrier.wait()

        c = btcp.client_socket.BTCPClientSocket(DEFAULT_WINDOW, DEFAULT_TIMEOUT)
        c.connect()
        barrier.wait() # wait for connection to start replaying recording
        with c._lossy_layer.effect(Replay, recorder) as replay:
            c.send(b"Hello world, again!")
            replay.wait()
        c.shutdown()

    @staticmethod
    def _old_segments_server(barrier):
        s = btcp.server_socket.BTCPServerSocket(DEFAULT_WINDOW, DEFAULT_TIMEOUT)
        s.accept()
        rh = RecvHelper(s)
        rh.expect(b"Hello world!")
        rh.expect_closed()
        s.close()
        barrier.wait()
        barrier.reset()
        s = btcp.server_socket.BTCPServerSocket(DEFAULT_WINDOW, DEFAULT_TIMEOUT)
        rh = RecvHelper(s)
        s.accept()
        barrier.wait()
        rh.expect_closed(b"Hello world, again!")


    def test_20_also_close(self): 
        run_in_separate_processes((), 
                                  T._also_close_client, 
                                  T._also_close_server)
        # no barrier here -shutdown should make sure its final acks are sent

    @staticmethod
    def _also_close_client():
        c = btcp.client_socket.BTCPClientSocket(DEFAULT_WINDOW, DEFAULT_TIMEOUT)
        c.connect()
        c.send(b"Hello world!")
        c.shutdown()

    @staticmethod
    def _also_close_server():
        s = btcp.server_socket.BTCPServerSocket(DEFAULT_WINDOW, DEFAULT_TIMEOUT)
        s.accept()
        RecvHelper(s).expect_closed(b"Hello world!")

    def test_21_duplication(self): 
        run_in_separate_processes((), 
                                  T._duplication_client, 
                                  T._duplication_server, timeout=5)
    @staticmethod
    def _duplication_client():  
        c = btcp.client_socket.BTCPClientSocket(DEFAULT_WINDOW, DEFAULT_TIMEOUT)
        with c._lossy_layer.effect(Duplication):
            c.connect()
            c.send(b"Hello world!")
            c.shutdown()

    @staticmethod
    def _duplication_server():
        s = btcp.server_socket.BTCPServerSocket(DEFAULT_WINDOW, DEFAULT_TIMEOUT)
        s.accept()
        RecvHelper(s).expect_closed(b"Hello world!")

    def test_21_duplication_no_shutdown(self): 
        run_in_separate_processes((multiprocessing.Barrier(2),), 
                                  T._duplication_client_no_shutdown, 
                                  T._duplication_server_no_shutdown, timeout=5)
    @staticmethod
    def _duplication_client_no_shutdown(barrier):
        c = btcp.client_socket.BTCPClientSocket(DEFAULT_WINDOW, DEFAULT_TIMEOUT)
        with c._lossy_layer.effect(Duplication):
            c.connect()
            c.send(b"Hello world 1!")
            c.send(b"Hello world 2!")
            barrier.wait()

    @staticmethod
    def _duplication_server_no_shutdown(barrier):
        s = btcp.server_socket.BTCPServerSocket(DEFAULT_WINDOW, DEFAULT_TIMEOUT)
        s.accept()
        RecvHelper(s).expect(b"Hello world 1!")
        RecvHelper(s).expect(b"Hello world 2!")
        barrier.wait()

    def test_22_corrupted_duplicates(self): 
        # Sends a duplicate with bitflips first 
        #  - should be caught by properly implemented checksums
        # It's easier to deal with this than normal bitflips, as retransmission is not required.
        run_in_separate_processes((), 
                                  T._corrupted_duplicates_client, 
                                  T._corrupted_duplicates_server, timeout=5)
    @staticmethod
    def _corrupted_duplicates_client():
        c = btcp.client_socket.BTCPClientSocket(DEFAULT_WINDOW, DEFAULT_TIMEOUT)
        c.connect()
        c.send(b"Hello world!")
        c.shutdown()

    @staticmethod
    def _corrupted_duplicates_server():
        s = btcp.server_socket.BTCPServerSocket(DEFAULT_WINDOW, DEFAULT_TIMEOUT)
        with s._lossy_layer.effect(Duplication, first_effect=CorruptReceivedData):
            s.accept()
            RecvHelper(s).expect_closed(b"Hello world!")

    def test_22_corrupted_duplicates_no_shutdown(self): 
        # Sends a duplicate with bitflips first 
        #  - should be caught by properly implemented checksums
        # It's easier to deal with this than normal bitflips, as retransmission is not required.
        run_in_separate_processes((multiprocessing.Barrier(2),), 
                                  T._corrupted_duplicates_client_no_shutdown, 
                                  T._corrupted_duplicates_server_no_shutdown, timeout=5)
    @staticmethod
    def _corrupted_duplicates_client_no_shutdown(barrier):
        c = btcp.client_socket.BTCPClientSocket(DEFAULT_WINDOW, DEFAULT_TIMEOUT)
        c.connect()
        c.send(b"Hello world!")
        barrier.wait()

    @staticmethod
    def _corrupted_duplicates_server_no_shutdown(barrier):
        s = btcp.server_socket.BTCPServerSocket(DEFAULT_WINDOW, DEFAULT_TIMEOUT)
        with s._lossy_layer.effect(Duplication, first_effect=CorruptReceivedData):
            s.accept()
            RecvHelper(s).expect(b"Hello world!")
            barrier.wait()
    
    def test_30_reordering(self): 
        # If this one fails, you might not be keeping track of sequence numbers correctly
        run_in_separate_processes((), 
                                  T._reordering_client, 
                                  T._reordering_server, timeout=5)
    @staticmethod
    def _reordering_client():
        c = btcp.client_socket.BTCPClientSocket(DEFAULT_WINDOW, DEFAULT_TIMEOUT)
        c.connect()
        c.send(b"Hello world 1!")
        c.send(b"Hello world 2!")
        c.shutdown()

    @staticmethod
    def _reordering_server():
        s = btcp.server_socket.BTCPServerSocket(DEFAULT_WINDOW, DEFAULT_TIMEOUT)
        s.accept()
        rh = RecvHelper(s)
        with s._lossy_layer.effect(ReorderReceived):
            rh.expect(b"Hello world 1!")
            rh.expect(b"Hello world 2!")
        rh.expect_closed()

    def test_30_reordering_no_shutdown(self): 
        # If this one fails, you might not be keeping track of sequence numbers correctly
        run_in_separate_processes((multiprocessing.Barrier(2),), 
                                  T._reordering_client_no_shutdown, 
                                  T._reordering_server_no_shutdown, timeout=5)
    @staticmethod
    def _reordering_client_no_shutdown(barrier):
        c = btcp.client_socket.BTCPClientSocket(DEFAULT_WINDOW, DEFAULT_TIMEOUT)
        c.connect()
        c.send(b"Hello world 1!")
        c.send(b"Hello world 2!")
        barrier.wait()

    @staticmethod
    def _reordering_server_no_shutdown(barrier):
        s = btcp.server_socket.BTCPServerSocket(DEFAULT_WINDOW, DEFAULT_TIMEOUT)
        s.accept()
        rh = RecvHelper(s)
        with s._lossy_layer.effect(ReorderReceived):
            rh.expect(b"Hello world 1!")
            rh.expect(b"Hello world 2!")
        barrier.wait()


    def test_31_syns(self): 
        # crashes when the first segment from each peer does not have a SYN,
        # or when later segments do
        run_in_separate_processes((multiprocessing.Barrier(2),), 
                                              T._syns_client, 
                                              T._syns_server, timeout=5)
    @staticmethod
    def _syns_client(barrier):
        c = btcp.client_socket.BTCPClientSocket(DEFAULT_WINDOW, DEFAULT_TIMEOUT)
        with c._lossy_layer.effect(SynHygiene):
            c.connect()
            c.send(b"Hello world!")
            barrier.wait()

    @staticmethod
    def _syns_server(barrier):
        s = btcp.server_socket.BTCPServerSocket(DEFAULT_WINDOW, DEFAULT_TIMEOUT)
        with s._lossy_layer.effect(SynHygiene):
            s.accept()
            rh = RecvHelper(s)
            rh.expect(b"Hello world!")
            barrier.wait()


    def test_32_fins(self): 
        # crashes when peers send no FINs, or when new data is sent after a FIN
        run_in_separate_processes((), 
                                  T._fins_client, 
                                  T._fins_server, timeout=5)
    @staticmethod
    def _fins_client():
        c = btcp.client_socket.BTCPClientSocket(DEFAULT_WINDOW, DEFAULT_TIMEOUT)
        with c._lossy_layer.effect(FinHygiene) as fh:
            c.connect()
            c.send(b"Hello world!")
            c.shutdown()
            if not fh._had_fin:
                raise AssertionError("Client did not send FIN")


    @staticmethod
    def _fins_server():
        s = btcp.server_socket.BTCPServerSocket(DEFAULT_WINDOW, DEFAULT_TIMEOUT)
        with s._lossy_layer.effect(FinHygiene) as fh:
            s.accept()
            rh = RecvHelper(s)
            rh.expect_closed(b"Hello world!")
            if not fh._had_fin:
                raise AssertionError("Server did not send FIN")

    def test_40_large(self):
        run_in_separate_processes((multiprocessing.Barrier(2),), 
                                  T._large_client, 
                                  T._large_server, timeout=60)

    @staticmethod
    def _large_client(barrier):
        c = btcp.client_socket.BTCPClientSocket(DEFAULT_WINDOW, DEFAULT_TIMEOUT)
        c.connect()
        sh = SendHelper(c)
        N = 0x10000
        for i in range(N):
            if i%1000==0:
                print(f"Send {i} out of {N}")
            sh.send(f"#{i+1} of {N}".encode('ascii'))
        barrier.wait()

    @staticmethod
    def _large_server(barrier):
        s = btcp.server_socket.BTCPServerSocket(DEFAULT_WINDOW, DEFAULT_TIMEOUT)
        s.accept()
        rh = RecvHelper(s)
        N = 0x10000
        for i in range(N):
            rh.expect(f"#{i+1} of {N}".encode('ascii'))
        barrier.wait()

    def test_60_drop_every_other(self): 
        # In this test the server only gets retransmissions from the client after
        # a connection has been established
        run_in_separate_processes((), 
                                  T._drop_every_other_client, 
                                  T._drop_every_other_server, timeout=10)

    @staticmethod
    def _drop_every_other_client():
        c = btcp.client_socket.BTCPClientSocket(DEFAULT_WINDOW, DEFAULT_TIMEOUT)
        c.connect()
        for i in range(2):
            c.send(f"Hello world {i}!".encode())
        c.shutdown()

    @staticmethod
    def _drop_every_other_server():
        s = btcp.server_socket.BTCPServerSocket(DEFAULT_WINDOW, DEFAULT_TIMEOUT)
        rh = RecvHelper(s)
        s.accept()
        with s._lossy_layer.effect(DropSecondReceived):
            for i in range(2):
                rh.expect(f"Hello world {i}!".encode())
        rh.expect_closed()
    
    def test_60_drop_every_other_no_shutdown(self): 
        # In this test the server only gets retransmissions from the client after
        # a connection has been established
        run_in_separate_processes((multiprocessing.Barrier(2),), 
                                  T._drop_every_other_client_no_shutdown, 
                                  T._drop_every_other_server_no_shutdown, timeout=10)

    @staticmethod
    def _drop_every_other_client_no_shutdown(barrier):
        c = btcp.client_socket.BTCPClientSocket(DEFAULT_WINDOW, DEFAULT_TIMEOUT)
        c.connect()
        for i in range(2):
            c.send(f"Hello world {i}!".encode())
        barrier.wait()

    @staticmethod
    def _drop_every_other_server_no_shutdown(barrier):
        s = btcp.server_socket.BTCPServerSocket(DEFAULT_WINDOW, DEFAULT_TIMEOUT)
        rh = RecvHelper(s)
        s.accept()
        with s._lossy_layer.effect(DropSecondReceived):
            for i in range(2):
                rh.expect(f"Hello world {i}!".encode())
        barrier.wait()

    def test_61_window_in_flight(self): 
        # Crashes when more segments with data are in-flight than the window size permits.
        run_in_separate_processes((),
                                  T._window_in_flight_client, 
                                  T._window_in_flight_server, timeout=5)
    @staticmethod
    def _window_in_flight_client():
        c = btcp.client_socket.BTCPClientSocket(100, DEFAULT_TIMEOUT)
        c.connect()
        with c._lossy_layer.effect(InFlightWindow, 3) as wh:
            c.send(b"1"*1008)
            c.send(b"2"*1008)
            c.send(b"3"*1008)
            c.send(b"4"*1008)
            time.sleep(.5) # give the window a chance to overflow
            wh.release_segments()
            c.shutdown()

    @staticmethod
    def _window_in_flight_server():
        s = btcp.server_socket.BTCPServerSocket(3, DEFAULT_TIMEOUT)
        s.accept()
        rh = RecvHelper(s)
        rh.expect(b"1"*1008)
        rh.expect(b"2"*1008)
        rh.expect(b"3"*1008)
        rh.expect_closed(b"4"*1008)

    def test_61_window_in_flight_no_shutdown(self): 
        # Crashes when more segments with data are in-flight than the window size permits.
        run_in_separate_processes((multiprocessing.Barrier(2),),
                                  T._window_in_flight_client_no_shutdown, 
                                  T._window_in_flight_server_no_shutdown, timeout=5)
    @staticmethod
    def _window_in_flight_client_no_shutdown(barrier):
        c = btcp.client_socket.BTCPClientSocket(100, DEFAULT_TIMEOUT)
        c.connect()
        with c._lossy_layer.effect(InFlightWindow, 3) as wh:
            c.send(b"1"*1008)
            c.send(b"2"*1008)
            c.send(b"3"*1008)
            c.send(b"4"*1008)
            time.sleep(.5) # give the window a chance to overflow
            wh.release_segments()
            barrier.wait()

    @staticmethod
    def _window_in_flight_server_no_shutdown(barrier):
        s = btcp.server_socket.BTCPServerSocket(3, DEFAULT_TIMEOUT)
        s.accept()
        rh = RecvHelper(s)
        rh.expect(b"1"*1008)
        rh.expect(b"2"*1008)
        rh.expect(b"3"*1008)
        rh.expect(b"4"*1008)
        barrier.wait()

    def test_62_window(self): 
        # The client sends segments, but the server's application layer is slow to 'recv' them.
        # Crashes if the client does not respect the server's window size.
        # Requires dynamic window updating based on the 'window' value sent back in the server's ACKs.
        run_in_separate_processes((multiprocessing.Barrier(2),), 
                                  T._window_client, 
                                  T._window_server, timeout=5)
    @staticmethod
    def _window_client(barrier):
        c = btcp.client_socket.BTCPClientSocket(100, DEFAULT_TIMEOUT)
        c.connect()
        with c._lossy_layer.effect(Window, 3) as wh:
            c.send(b"1"*1008)
            c.send(b"2"*1008)
            c.send(b"3"*1008)
            c.send(b"4"*1008)
            time.sleep(.5) # give the window a chance to overflow
            barrier.wait()
            wh.stop_checking()
            c.shutdown()

    @staticmethod
    def _window_server(barrier):
        s = btcp.server_socket.BTCPServerSocket(3, DEFAULT_TIMEOUT)
        s.accept()
        barrier.wait() # wait with recv-ing
        rh = RecvHelper(s)
        rh.expect(b"1"*1008)
        rh.expect(b"2"*1008)
        rh.expect(b"3"*1008)
        rh.expect_closed(b"4"*1008)


    def test_70_drop_every_other_ack(self): 
        # In this test the client only gets retransmissions from the server
        # once a connection has been established
        run_in_separate_processes((), 
                                  T._drop_every_other_ack_client, 
                                  T._drop_every_other_ack_server, timeout=10)

    @staticmethod
    def _drop_every_other_ack_client():
        c = btcp.client_socket.BTCPClientSocket(DEFAULT_WINDOW, DEFAULT_TIMEOUT)
        c.connect()
        with c._lossy_layer.effect(DropSecondReceived):
            for i in range(3):
                c.send(f"Hello world {i}!".encode())
            c.shutdown()

    @staticmethod
    def _drop_every_other_ack_server():
        s = btcp.server_socket.BTCPServerSocket(DEFAULT_WINDOW, DEFAULT_TIMEOUT)
        rh = RecvHelper(s)
        s.accept()
        for i in range(3):
            rh.expect(f"Hello world {i}!".encode())
        rh.expect_closed()

    def test_70_drop_every_other_ack_no_shutdown(self): 
        # In this test the client only gets retransmissions from the server
        # once a connection has been established
        run_in_separate_processes((multiprocessing.Barrier(2),), 
                                  T._drop_every_other_ack_client_no_shutdown, 
                                  T._drop_every_other_ack_server_no_shutdown, timeout=10)

    @staticmethod
    def _drop_every_other_ack_client_no_shutdown(barrier):
        c = btcp.client_socket.BTCPClientSocket(DEFAULT_WINDOW, DEFAULT_TIMEOUT)
        c.connect()
        with c._lossy_layer.effect(DropSecondReceived):
            for i in range(3):
                c.send(f"Hello world {i}!".encode())
            barrier.wait()

    @staticmethod
    def _drop_every_other_ack_server_no_shutdown(barrier):
        s = btcp.server_socket.BTCPServerSocket(DEFAULT_WINDOW, DEFAULT_TIMEOUT)
        rh = RecvHelper(s)
        s.accept()
        for i in range(3):
            rh.expect(f"Hello world {i}!".encode())
        barrier.wait()

    def test_80_drop_every_other_always(self): 
        # In this test both client and server only get retransmissions,
        # including the segments from the handshakes.
        run_in_separate_processes((), 
                                  T._drop_every_other_always_client, 
                                  T._drop_every_other_always_server, timeout=10)

    @staticmethod
    def _drop_every_other_always_client():
        c = btcp.client_socket.BTCPClientSocket(DEFAULT_WINDOW, DEFAULT_TIMEOUT)
        with c._lossy_layer.effect(DropSecondReceived):
            c.connect()
            for i in range(3):
                c.send(f"Hello world {i}!".encode())
            c.shutdown()

    @staticmethod
    def _drop_every_other_always_server():
        s = btcp.server_socket.BTCPServerSocket(DEFAULT_WINDOW, DEFAULT_TIMEOUT)
        rh = RecvHelper(s)
        with s._lossy_layer.effect(DropSecondReceived):
            s.accept()
            for i in range(3):
                rh.expect(f"Hello world {i}!".encode())
            rh.expect_closed()

    def test_80_drop_every_other_always_no_shutdown(self): 
        # In this test both client and server only get retransmissions,
        # including the segments from the handshakes.
        run_in_separate_processes((multiprocessing.Barrier(2),), 
                                  T._drop_every_other_always_client_no_shutdown, 
                                  T._drop_every_other_always_server_no_shutdown, timeout=10)

    @staticmethod
    def _drop_every_other_always_client_no_shutdown(barrier):
        c = btcp.client_socket.BTCPClientSocket(DEFAULT_WINDOW, DEFAULT_TIMEOUT)
        with c._lossy_layer.effect(DropSecondReceived):
            c.connect()
            for i in range(3):
                c.send(f"Hello world {i}!".encode())
            barrier.wait()

    @staticmethod
    def _drop_every_other_always_server_no_shutdown(barrier):
        s = btcp.server_socket.BTCPServerSocket(DEFAULT_WINDOW, DEFAULT_TIMEOUT)
        rh = RecvHelper(s)
        with s._lossy_layer.effect(DropSecondReceived):
            s.accept()
            for i in range(3):
                rh.expect(f"Hello world {i}!".encode())
            barrier.wait()

    def test_90_reconnect(self): 
        run_in_separate_processes((), 
                                  T._reconnect_client, 
                                  T._reconnect_server, timeout=10)
    @staticmethod
    def _reconnect_client():
        c = btcp.client_socket.BTCPClientSocket(DEFAULT_WINDOW, DEFAULT_TIMEOUT)
        c.connect()
        c.send(b"Hello world!")
        c.shutdown()
        c.connect()
        c.send(b"Hello world, again!")
        c.shutdown()

    @staticmethod
    def _reconnect_server():
        s = btcp.server_socket.BTCPServerSocket(DEFAULT_WINDOW, DEFAULT_TIMEOUT)
        rh = RecvHelper(s)
        s.accept()
        rh.expect_closed(b"Hello world!")
        s.accept()
        rh.expect_closed(b"Hello world, again!")




class Identity(btcp.lossy_layer.BasicHandler):
    """Handler creator that does nothing in particular"""
    pass

class SegmentLenChecker(btcp.lossy_layer.BasicHandler):
    """Handler that checks that the segment length is 1018."""
    def __init__(self, old_handler):
        super().__init__(old_handler)
    
    def send_segment(self, segment):
        if len(segment) != 1018:
            raise AssertionError(f"sent segment length, {len(segment)}, is not 1018!")
        self._old_handler.send_segment(segment)

    def segment_received(self, segment):
        if len(segment) != 1018:
            raise AssertionError(f"received segment length, {len(segment)}, is not 1018!")
        self._old_handler.segment_received(segment)


class RecvHelper:
    """Helper to receive the desired number of bytes from a BTCP socket."""
    def __init__(self, btcp_socket):
        self._btcp_socket = btcp_socket
        self._buffered = b""

    def _pop_buffered(self):
        res, self._buffered = self._buffered, b""
        return res

    def recv_exactly(self, length):
        """Blocks until we have received `length` bytes, and returns these bytes.

        Only returns less if the BTCP connection is closed, which the BTCP socket
        indicated by having recv() return b"" """
        buf = self._pop_buffered()
        while len(buf) < length:
            extra = self._btcp_socket.recv()
            if extra == b"":
                return buf 
            buf += extra
        res,self._buffered = buf[:length],buf[length:]
        return res

    def expect(self, data):
        result = self.recv_exactly(len(data))
        if data != result:
            raise AssertionError(f"expected to receive {repr(data)}, but got {repr(result)}")

    def expect_closed(self, data=None):
        if data!=None:
            self.expect(data)
        result = self._btcp_socket.recv()
        if result != b"":
            raise AssertionError(f"expected the BTCP socket to be closed, but recv() returned {repr(result)} instead of b\"\"")
            
class SendHelper:
    """Helper to send the desired number of bytes on a BTCP socket."""
    def __init__(self, btcp_socket):
        self._btcp_socket = btcp_socket
    
    def send(self, data):
        """Blocks until all data is sent over the socket"""
        while len(data) > 0:
            bytes_sent = self._btcp_socket.send(data)
            data = data[bytes_sent:]
            if bytes_sent == 0:
                time.sleep(0.05)
        

class CorruptReceivedData(btcp.lossy_layer.BasicHandler):
    """Handler that replaces all received segments' data by "check checksum!" """
    def __init__(self, old_handler):
        super().__init__(old_handler)

    def segment_received(self, segment):
        segment = bytearray(segment)
        check_checksum = b"check checksum! "
        for i in range(btcp.constants.HEADER_SIZE, 
                       btcp.constants.SEGMENT_SIZE):
            segment[i] = check_checksum[i % len(check_checksum)]
        self._old_handler.segment_received(bytes(segment))


class Duplication(btcp.lossy_layer.BasicHandler):
    """Handler that duplicates every outgoing and incoming segment.

    An effect can be applied to the first and second instances of each such segment
    using the `first_effect` and `second_effect` arguments.

    Ticks are only sent through the first_effect handler."""
    def __init__(self, old_handler, first_effect=Identity, second_effect=Identity):
        super().__init__(old_handler)
        self._first_handler = first_effect(old_handler)
        self._second_handler = second_effect(old_handler)
    
    def send_segment(self, segment):
        self._first_handler.send_segment(segment)
        self._second_handler.send_segment(segment)

    def segment_received(self, segment):
        self._first_handler.segment_received(segment)
        self._second_handler.segment_received(segment)

    def tick(self):
        self._first_handler.tick()


class ReorderReceived(btcp.lossy_layer.BasicHandler):
    """Handler that swaps consecutive packets. """
    def __init__(self, old_handler, max_holding_ticks=2):
        super().__init__(old_handler)
        self._held_segment = None
        self._ticks_left = None
        self._max_holding_ticks = max_holding_ticks

    def segment_received(self, segment):
        if self._held_segment:
            self._old_handler.segment_received(segment)
            self._release_held_segment()
        else:
            self._held_segment = segment
            self._ticks_left = self._max_holding_ticks

    def tick(self):
        self._old_handler.tick()
        if self._ticks_left == None:
            return
        self._ticks_left -= 1
        if self._ticks_left <= 0:
            self._release_held_segment()

    def _release_held_segment(self):
        assert(self._held_segment != None)
        self._old_handler.segment_received(self._held_segment)
        self._held_segment = None
        self._ticks_left = None

class DropSecondReceived(btcp.lossy_layer.BasicHandler):
    """Handler that drops every other appearance of the same sequence number in received segments"""
    def __init__(self, old_handler):
        super().__init__(old_handler)
        self._seen = set()

    def segment_received(self, segment):
        if segment[0:2] in self._seen:
            logger.debug(f"not dropping segment {seg_print(segment)}")
            self._old_handler.segment_received(segment)
            self._seen.remove(segment[0:2])
            return
        logger.debug(f"dropping segment {seg_print(segment)}")
        self._seen.add(segment[0:2])


class SynHygiene(btcp.lossy_layer.BasicHandler):
    """Handler that crashes when the first segment has no SYN or another segment (not counting
    retransmissions) does."""
    def __init__(self, old_handler):
        super().__init__(old_handler)
        self.syn_segment = None

    def send_segment(self, segment):
        if seg_syn_set(segment):
            if self.syn_segment == None:
                self.syn_segment = segment
            elif self.syn_segment != segment:
                raise AssertionError(f"Segment has SYN set, but is not (a retransmission of) the first segment.\nnew segment: {seg_print(segment)}\nold segment: {seg_print(self.syn_segment)}")   

        elif self.syn_segment == None:
            raise AssertionError("The first segment sent has no SYN set")

        self._old_handler.send_segment(segment)


class FinHygiene(btcp.lossy_layer.BasicHandler):
    """Handler that crashes when a segment is sent after a FIN that is not a ratransmission
    or a FIN."""
    def __init__(self, old_handler):
        super().__init__(old_handler)
        self._had_fin = False
        self._saw = set()

    def send_segment(self, segment):
        if self._had_fin:
            if segment not in self._saw and seg_len(segment)>0:
                raise AssertionError("Segment after FIN has data but is not a retransmission")
        else:
            self._saw.add(segment)
            if seg_fin_set(segment):
                self._had_fin = True

        self._old_handler.send_segment(segment)


class InFlightWindow(btcp.lossy_layer.BasicHandler):
    """Handler that checks whether the during the handshake advertised window size is respected 
    for segments being sent by holding segments 'in flight' until released. 
    If more segments with data are held up than the window size, the window size is not respected."""
    def __init__(self, old_handler, window_size):
        super().__init__(old_handler)
        
        self._window_size = window_size
        self._held_up = []
        self._seen = set() # for detecting retransmissions
        self._seen_data_segment_count = 0
        self._released = False

    def send_segment(self, segment):
        logger.debug(f"window tester: got segment: {seg_print(segment)}")
        if self._released:
            if len(self._held_up)>0:
                for hs in self._held_up:
                    self._old_handler.send_segment(hs)
                self._held_up = []
            self._old_handler.send_segment(segment)
            return
        if seg_len(segment) > 0 and segment not in self._seen:
            logger.debug(f"window tester: added data segment to window: {seg_print(segment)}")
            self._seen.add(segment)
            self._seen_data_segment_count += 1
            if self._seen_data_segment_count > self._window_size:
                raise AssertionError(f"Window size {self._window_size} not respected")
        self._held_up.append(segment)

    def release_segments(self):
        self._released = True


class Window(btcp.lossy_layer.BasicHandler):
    """Handler to crudely check whether the window is respected.
    It assumes that the server's application layer does not call recv at all until
    `stop_checking` is called."""
    def __init__(self, old_handler, window_size):
        super().__init__(old_handler)
        
        self._window_size = window_size
        self._seen = set() # for detecting retransmissions
        self._seen_data_segment_count = 0
        self._stopped = False

    def send_segment(self, segment):
        logger.debug(f"window tester: got segment: {seg_print(segment)}")
        self._old_handler.send_segment(segment)
        if self._stopped:
            return
        if seg_len(segment) > 0 and segment not in self._seen:
            self._seen.add(segment)
            self._seen_data_segment_count += 1
            if self._seen_data_segment_count > self._window_size:
                raise AssertionError(f"Window size {self._window_size} not respected")

    def stop_checking(self):
        self._stopped = True


class Record(btcp.lossy_layer.BasicHandler):
    """Handler that records segments"""
    def __init__(self, old_handler):
        super().__init__(old_handler)
        self._sent_segments = []
        self._received_segments = []
        self._t0 = time.time()

    def t(self):
        return time.time()-self._t0

    def send_segment(self, segment):
        self._sent_segments.append((self.t(), segment))
        logger.debug(f"recorded sent segment {seg_print(segment)}")
        self._old_handler.send_segment(segment)

    def segment_received(self, segment):
        self._received_segments.append((self.t(), segment))
        logger.debug(f"recorded received segment {seg_print(segment)}")
        self._old_handler.segment_received(segment)

class Replay(btcp.lossy_layer.BasicHandler):
    """Handler that replays a recording"""
    def __init__(self, old_handler, recording):
        super().__init__(old_handler)
        self._sent_segments = list(reversed(recording._sent_segments))
        self._received_segments = list(reversed(recording._received_segments))
        logger.debug(f"replaying {len(self._sent_segments)} sent and {len(self._received_segments)} received segments")
        self._t0 = time.time()
        self._done = threading.Event()

    def t(self):
        return time.time()-self._t0

    def tick(self):
        t = self.t()
        while self._received_segments and self._received_segments[-1][0] < t:
            _, segment = self._received_segments.pop()
            logger.debug(f"replaying received segment {seg_print(segment)}")
            self._old_handler.segment_received(segment)
        while self._sent_segments and self._sent_segments[-1][0] < t:
            _, segment = self._sent_segments.pop()
            logger.debug(f"replaying sent segment with {seg_print(segment)}")
            self._old_handler.send_segment(segment)
        if not (self._sent_segments or self._received_segments):
            self._done.set()
        self._old_handler.tick()

    def wait(self):
        """Waits until all segments have been replayed"""
        self._done.wait()
        

def seg_syn_set(segment):
    return segment[4] & 4 == 4

def seg_ack_set(segment):
    return segment[4] & 2 == 2

def seg_fin_set(segment):
    return segment[4] & 1 == 1

def seg_len(segment):
    return struct.unpack_from("!H", segment, 6)[0]

PROPERLY_PRINTABLE = set(string.printable) - (set(string.whitespace) - set(" "))

def seg_print(segment):
    ack_set = seg_ack_set(segment)
    ack_info = f"A{segment[2:4].hex()}" if seg_ack_set(segment) else "-----" 
    l = seg_len(segment)
    lp = min(l, 20)
    data_snip = ''.join(chr(c) if chr(c) in PROPERLY_PRINTABLE else '?' for c in segment[10:10+lp])
    if l>lp:
        data_snip += '...'

    return (f"{'S' if seg_syn_set(segment) else '-'}"
            f"{'F' if seg_fin_set(segment) else '-'}"
            f" #{segment[0:2].hex()} {ack_info} W{segment[5:6].hex()} {data_snip}")
            


def run_in_separate_processes(args, *targets, timeout=5):
    """ Run the given functions with args in separate processes and terminates them if they haven't finished within `timeout` seconds.  We use separate processes instead of threads, because threads cannot be aborted. Returns True if all the processes exited without exception or timeout. """

    error_msg = None

    # queue via which the processes signal their completion
    q = multiprocessing.Queue(len(targets))

    processes_left = len(targets)

    processes = list([ multiprocessing.Process(
        target=run_process, 
        args=(target, q, idx, logger.getEffectiveLevel(), __suppress_nie)+args, 
        name=f"{repr(target.__name__)}"
    ) for (idx,target) in enumerate(targets)])

    for process in processes:
        process.start()

    deadline = time.time() + timeout

    while processes_left > 0:
        eta = deadline - time.time()
        if eta < 0:
            break # get didn't time out, but we ran out of time nonetheless
        logger.info(f"waiting for a process to finish for {eta:.3f} seconds")
        try:
            (idx, success) = q.get(True, eta)
        except queue.Empty:
            # timeout
            error_msg = ("""

        T I M E O U T

    Woops, it looks like your code hangs. 

    Check above whether the client, server, or both timed out.

""")
            for process in processes:
                if process.is_alive():
                    logger.error(f"Process {process.name} ({process.pid}) timed out")
            break

        process = processes[idx]
        process.join()
        processes_left -= 1
        if not success:
            error_msg = (f"""

        C R A S H

    Woops, process {process.name} ({process.pid}) crashed.

    Check the traceback and error message above.

""")
            break
        logger.info(f"Process {process.name} ({process.pid}) completed gracefully")
    else:
        return # while loop ended without break - all processes joined before deadline

    assert(error_msg != None)

    # before we raise error_msg, first make sure all the processes we spawned are stopped
    for process in processes:
        if process.is_alive():
            logger.warning(f"  terminating process {process.name} ({process.pid})...")
            process.terminate()
    for process in processes:
        if process.is_alive():
            logger.warning(f"  waiting for process {process.name} ({process.pid}) exitcode={process.exitcode} to join...")
            process.join()
            logger.warning(f"    process {process.name} ({process.pid}) exited with code {process.exitcode}")
        else:
            logger.warning(f"  process {process.name} ({process.pid}) has already exited wih code {process.exitcode}")

    raise RuntimeError(error_msg)

def run_process(func, queue, idx, loglevel, suppress_nie, *args):
    configure_globals(loglevel=loglevel, suppress_nie=suppress_nie) # globals are not shared between processes
    success = False
    try:
        func(*args)
        success = True
    finally:
        queue.put_nowait((idx, success))

__suppress_nie = False

def configure_globals(loglevel, suppress_nie):
    logging.basicConfig(level=loglevel,
            format="%(asctime)s:%(name)s:%(levelname)s:%(message)s")

    if suppress_nie:
        logger.warning(f"suppressing NotImplementedErrors on {os.getpid()}")
        btcp.btcp_socket.__suppress_nie = True

    # store suppress_nie so we can look it up later
    global __suppress_nie
    __suppress_nie = suppress_nie


if __name__ == "__main__":
    # Parse command line arguments
    import argparse
    parser = argparse.ArgumentParser(description=f"""bTCP unit tests
        
Please also have a look at the Python unittest module options:

  {os.path.basename(__file__)} -- -h

""", formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-l", "--loglevel",
                        choices=["DEBUG", "INFO", "WARNING",
                                 "ERROR", "CRITICAL"],
                        help="Log level "
                             "for the python built-in logging module. ",
                        default=DEFAULT_LOGLEVEL)
    parser.add_argument("-s", "--suppress-not-implemented-errors",
                        action="store_true",
                        help="Suppresses initial NotImplementedErrors")
    args, extra = parser.parse_known_args()

    if extra and extra[0] == '--':
        del extra[0]
    # We do this so that:
    #   python3 unittests.py -h     # prints help for BTCP unittests module
    #   python3 unittests.py -- -h  # prints usage for Python unittest module 

    if args.loglevel == DEFAULT_LOGLEVEL:
        print(f"""NB:  Using default {DEFAULT_LOGLEVEL} loglevel; if you need more details, use:

  python3 {os.path.basename(__file__)} -l DEBUG

""")

    configure_globals(loglevel=getattr(logging, args.loglevel.upper()),
                      suppress_nie=(args.suppress_not_implemented_errors==True))

    # Pass the extra arguments to unittest
    sys.argv[1:] = extra


    # Start test suite
    unittest.main()
