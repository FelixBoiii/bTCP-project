from btcp.btcp_socket import BTCPSocket, BTCPStates, raise_NotImplementedError
from btcp.lossy_layer import LossyLayer
from btcp.constants import *

import queue
import logging
import random
import time


logger = logging.getLogger(__name__)


class BTCPClientSocket(BTCPSocket):
    """bTCP client socket
    A client application makes use of the services provided by bTCP by calling
    connect, send, shutdown, and close.

    You're implementing the transport layer, exposing it to the application
    layer as a (variation on) socket API.

    To implement the transport layer, you also need to interface with the
    network (lossy) layer. This happens by both calling into it
    (LossyLayer.send_segment) and providing callbacks for it
    (BTCPClientSocket.lossy_layer_segment_received, lossy_layer_tick).

    Your implementation will operate in two threads, the network thread,
    where the lossy layer "lives" and where your callbacks will be called from,
    and the application thread, where the application calls connect, send, etc.
    This means you will need some thread-safe information passing between
    network thread and application thread.
    Writing a boolean or enum attribute in one thread and reading it in a loop
    in another thread should be sufficient to signal state changes.
    Lists, however, are not thread safe, so to pass data and segments around
    you probably want to use queues*, or a similar thread safe collection.

    * See <https://docs.python.org/3/library/queue.html>
    """


    def __init__(self, window, timeout, isn=None):
        """Constructor for the bTCP client socket. Allocates local resources
        and starts an instance of the Lossy Layer.
        """
        logger.debug("__init__ called")
        super().__init__(window, timeout, isn)
        self._lossy_layer = LossyLayer(self, CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT)

        # The data buffer used by send() to send data from the application
        # thread into the network thread. Bounded in size.
        self._sendbuf = queue.Queue(maxsize=1000)
        self._lossy_layer.start_network_thread()
        #self._handshakeQueue = queue.Queue()
        self._not_ack_segments = []
        self._oldest_timestamp = time.time()        
        
        self._server_window = 0x50

        logger.info("Socket initialized with sendbuf size 1000")


    ###########################################################################
    ### The following section is the interface between the transport layer  ###
    ### and the lossy (network) layer. When a segment arrives, the lossy    ###
    ### layer will call the lossy_layer_segment_received method "from the   ###
    ### network thread". In that method you should handle the checking of   ###
    ### the segment, and take other actions that should be taken upon its   ###
    ### arrival.                                                            ###
    ###                                                                     ###
    ### Of course you can implement this using any helper methods you want  ###
    ### to add.                                                             ###
    ###########################################################################

    def lossy_layer_segment_received(self, segment):
        """Called by the lossy layer whenever a segment arrives.

        Things you should expect to handle here (or in helper methods called
        from here):
            - checksum verification (and deciding what to do if it fails)
            - receiving syn/ack during handshake
            - receiving ack and registering the corresponding segment as being
              acknowledged
            - receiving fin/ack during termination
            - any other handling of the header received from the server

        Remember, we expect you to implement this *as a state machine!*
        You have quite a bit of freedom in how you do this, but we at least
        expect you to *keep track of the state the protocol is in*,
        *perform the appropriate state transitions based on events*, and
        *alter behaviour based on that state*.

        So when you receive the segment, do the processing that is common
        for all states (verifying the checksum, parsing it into header values
        and data...).
        Then check the protocol state, do appropriate state-based processing
        (e.g. a FIN is not an acceptable segment in ACCEPTING state, whereas a
        SYN is).
        Finally, do post-processing that is common to all states.

        You could e.g. implement the state-specific processing in a helper
        function per state, and simply call the appropriate helper function
        based on which state you are in.
        In that case, it will be very helpful to split your processing into
        smaller helper functions, that you can combine as needed into a larger
        function for each state.
        """
        logger.debug("lossy_layer_segment_received called")
        logger.debug(segment)
        
        #ignores segment if it is not the right size
        if(len(segment) != SEGMENT_SIZE):
            logger.debug("not the right length")  
            
        #unpack segment and get the payload
        seqnum, acknum, flag_byte, window, length, checksum = self.unpack_segment_header(segment[:HEADER_SIZE])
        chunk = segment[HEADER_SIZE:HEADER_SIZE + length]

        #verify the checksum, if wrong ignore the segment 
        if not self.verify_checksum(segment):
            logger.warning("Checksum verification failed")
            return
            
        #all states of the server socket
        match self._state:
            case BTCPStates.SYN_SENT:
                self._syn_send_segment_received(seqnum, acknum, flag_byte, window, length, checksum, chunk)
            case BTCPStates.CLOSED:
                self._closed_segment_received(seqnum, acknum, flag_byte, window, length, checksum, chunk)
            case BTCPStates.FIN_SENT:
                self._fin_sent_segment_received(seqnum, acknum, flag_byte, window, length, checksum, chunk)
            case BTCPStates.ESTABLISHED:
                self._established_segment_received(seqnum, acknum, flag_byte, window, length, checksum, chunk)
            case _:
                logger.warning(f"Unexpected state: {self._state}")
    
    #handles the segment in the syn_send state
    def _syn_send_segment_received(self, seqnum, acknum, flag_byte, window, length, checksum, chunk):
        if (flag_byte >> 1) & 1:
            logger.warning(f"syn_sent btcpstate = established for client new ack={seqnum}")
            
            self._server_window = window
            segment = self.create_and_send_segment(self._seqnum, BTCPSocket.increment_seqnum(seqnum), ack_set=True)
            self._not_ack_segments.append((self._seqnum, segment))
            if not self._not_ack_segments:
                self._oldest_timestamp = time.time()
                
            self._state = BTCPStates.ESTABLISHED
            
        else:
            logger.warning("Expected SYN-ACK segment, but SYN flag not set")

    #handles the segment in the fin_sent state
    def _fin_sent_segment_received(self, seqnum, acknum, flag_byte, window, length, checksum, chunk):
        logger.debug("_fin_sent_segment_received called")
        
        if (flag_byte >> 1) & 1 and flag_byte & 1:
            logger.debug("fin_sent btcpstate = closed for client")
            self._state = BTCPStates.CLOSED
        else:
            logger.warning("Expected FIN-ACK segment, but ACK flag not set")
            _ = self.create_and_send_segment(self._seqnum, 0, fin_set=True)


    #handles the segment in the established state
    def _established_segment_received(self, seqnum, acknum, flag_byte, window, length, checksum, chunk):
        logger.debug("_established_segment_received called")
        if (flag_byte >> 1) & 1:
            self._server_window = window
            logger.debug("Recieved ack from server")
            
            #Go back n) enumerates over all not yet acknowledged packets
            # and finds the one that is acknowledged
            found_index = -1
            for i, (seq_num, _) in enumerate(self._not_ack_segments):
                if seq_num == acknum:
                    found_index = i
                    break
            
            #Go back n) deletes all packets that came before and including
            #the packet that was acknowledged from the list and resets the timer
            #if the list is not empty
            if found_index != -1:
                self._not_ack_segments = self._not_ack_segments[found_index + 1:]
                if not self._not_ack_segments:
                    self._oldest_timestamp = None
                else:
                    self._oldest_timestamp = time.time()
            
    def _closed_segment_received(self, seqnum, acknum, flag_byte, window, length, checksum, chunk):
        return
            
        

    def lossy_layer_tick(self):
        """Called by the lossy layer whenever no segment has arrived for
        TIMER_TICK milliseconds. Defaults to 100ms, can be set in constants.py.

        NOTE: Will NOT be called if segments are arriving; do not rely on
        simply counting calls to this method for an accurate timeout. If 10
        segments arrive, each 99 ms apart, this method will NOT be called for
        over a second!

        The primary use for this method is to be able to do things in the
        "network thread" even while no segments are arriving -- which would
        otherwise trigger a call to lossy_layer_segment_received.

        For example, checking for timeouts on acknowledgement of previously
        sent segments -- to trigger retransmission -- should work even if no
        segments are being received. Although you can't count these ticks
        themselves for the timeout, you can trigger the check from here.

        You will probably see some code duplication of code that doesn't handle
        the incoming segment among lossy_layer_segment_received and
        lossy_layer_tick. That kind of duplicated code would be a good
        candidate to put in a helper method which can be called from either
        lossy_layer_segment_received or lossy_layer_tick.
        """
        # Actually send all chunks available for sending.
        # Relies on an eventual exception to break from the loop when no data
        # is available.
        
        ##tijdelijk
        if self._not_ack_segments and self._oldest_timestamp is None:
            self._oldest_timestamp = time.time()
        
        
        ##tijdelijk
        
        
        #Go-back-n) if timeout resends all packages not yet acklowledged 
        if self._not_ack_segments and time.time() - self._oldest_timestamp > 0.5:
            logger.debug("go-back-n timer timeout. Resending segments")
            self._oldest_timestamp = time.time()
            for _, segment in self._not_ack_segments:
                self._lossy_layer.send_segment(segment)
        
        #Go-back-n) sends the amount of packets that is possible in the windowsize
        try:
            while len(self._not_ack_segments) < self._server_window:
                #logger.debug("Getting chunk from buffer.")
                chunk = self._sendbuf.get_nowait()
                
                #builds and sends segment, adds it to the not yet acknoledged
                # list and increments the sequence number
                segment = self.create_and_send_segment(self._seqnum, 0, length=len(chunk), payload=chunk)
                self._not_ack_segments.append((self._seqnum, segment))
                self._seqnum = BTCPSocket.increment_seqnum(self._seqnum)
                
                #resets the timeout timer if the list is empty
                if len(self._not_ack_segments) == 1:
                    self._oldest_timestamp = time.time()
                                
                
        except queue.Empty:
            logger.info("No (more) data was available for sending right now.")



    ###########################################################################
    ### You're also building the socket API for the applications to use.    ###
    ### The following section is the interface between the application      ###
    ### layer and the transport layer. Applications call these methods to   ###
    ### connect, shutdown (disconnect), send data, etc. Conceptually, this  ###
    ### happens in "the application thread".                                ###
    ###                                                                     ###
    ### Note that because this is the client socket, and our (initial)      ###
    ### implementation of bTCP is one-way reliable data transfer, there is  ###
    ### no recv() method available to the applications. You should still    ###
    ### be able to receive segments on the lossy layer, however, because    ###
    ### of acknowledgements and synchronization. You should implement that  ###
    ### above (in lossy_layer_...)                                          ###
    ###########################################################################

    def connect(self):
        """Perform the bTCP three-way handshake to establish a connection.

        connect should *block* (i.e. not return) until the connection has been
        successfully established or the connection attempt is aborted. You will
        need some coordination between the application thread and the network
        thread for this, because the syn/ack from the server will be received
        in the network thread.

        Hint: assigning to a boolean or enum attribute in thread A and reading
        it in a loop in thread B (preferably with a short sleep to avoid
        wasting a lot of CPU time) ensures that thread B will wait until the
        boolean or enum has the expected value. You can also put some kind of
        "signal" (e.g. BTCPSignals.CONNECT, or BTCPStates.FIN_SENT) in a Queue,
        and use a blocking get() on the other side to receive that signal.

        Since Python uses duck typing, and Queues can handle mixed types,
        you could even use the same queue to send a "connect signal", then
        all data chunks, then a "shutdown signal", into the network thread.
        That will take some tricky handling, however.

        We do not think you will need more advanced thread synchronization in
        this project.
        """
        
        # send syn segment, add it to the not acknoledge segments,increment sequence number and set state to syn_sent
        segment = self.create_and_send_segment(self._seqnum, 0, syn_set=True)
        self._not_ack_segments.append((self._seqnum, segment))
        self._seqnum = BTCPSocket.increment_seqnum(self._seqnum)
        self._state = BTCPStates.SYN_SENT
        
        while self._state != BTCPStates.ESTABLISHED:
            time.sleep(0.05)


    def send(self, data):
        """Send data originating from the application in a reliable way to the
        server.

        This method should *NOT* block waiting for acknowledgement of the data.


        You are free to implement this however you like, but the following
        explanation may help to understand how sockets *usually* behave and you
        may choose to follow this concept as well:

        The way this usually works is that "send" operates on a "send buffer".
        Once (part of) the data has been successfully put "in the send buffer",
        the send method returns the number of bytes it was able to put in the
        buffer. The actual sending of the data, i.e. turning it into segments
        and sending the segments into the lossy layer, happens *outside* of the
        send method (e.g. in the network thread).
        If the socket does not have enough buffer space available, it is up to
        the application to retry sending the bytes it was not able to buffer
        for sending.

        Again, you should feel free to deviate from how this usually works.
        However, you should *not* deviate from the behaviour of returning the
        amount of bytes you were actually able to send, regardless of whether
        you use a send buffer or actually send the segments here.

        Note that our rudimentary implementation here already chunks the data
        in maximum 1008-byte bytes objects because that's the maximum a segment
        can carry. If a chunk is smaller we do *not* pad it here, that gets
        done later.
        """
        #logger.debug("send called")
        #raise_NotImplementedError("Only rudimentary implementation of send present. Read the comments & code of client_socket.py, then remove the NotImplementedError.")

        # Example with a finite buffer: a queue with at most 1000 chunks,
        # for a maximum of 985KiB data buffered to get turned into packets.
        # See BTCPSocket__init__() in btcp_socket.py for its construction.
        datalen = len(data)
        logger.debug("%i bytes passed to send", datalen)
        sent_bytes = 0
        logger.info("Queueing data for transmission")
        try:
            while sent_bytes < datalen:
                logger.debug("Cumulative data queued: %i bytes", sent_bytes)
                # Slide over data using sent_bytes. Reassignments to data are
                # too expensive when data is large.
                chunk = data[sent_bytes:sent_bytes+PAYLOAD_SIZE]
                logger.debug("Putting chunk in send queue.")
                self._sendbuf.put_nowait(chunk)
                sent_bytes += len(chunk)
        except queue.Full:
            logger.info("Send queue full.")
        logger.info("Managed to queue %i out of %i bytes for transmission",
                    sent_bytes,
                    datalen)
        return sent_bytes


    def shutdown(self):
        """Perform the bTCP three-way finish to shutdown the connection.

        shutdown should *block* (i.e. not return) until the connection has been
        successfully terminated or the disconnect attempt is aborted. You will
        need some coordination between the application thread and the network
        thread for this, because the fin/ack from the server will be received
        in the network thread.
        """
        logger.debug("shutdown called")
        while not self._sendbuf.empty() or len(self._not_ack_segments) > 0:
            time.sleep(0.05)
        
        self._state = BTCPStates.FIN_SENT
        segment = self.create_and_send_segment(self._seqnum, 0, fin_set=True)
        self._not_ack_segments.append((self._seqnum, segment))

        if not self._not_ack_segments:
            self._oldest_timestamp = time.time()

        start_time = time.time()
        while self._state != BTCPStates.CLOSED or (time.time() - start_time) < self._timeout_secs:
            time.sleep(0.5)
        
        #if the max tries is met the client goes to closed mode
        self._state = BTCPStates.CLOSED
        logger.debug("client is closed")

        # We're guessing the server will timeout in timeout_secs seconds,
        # and that we will have enough time in the remaining .5 * timeout_secs
        # to send anything the application layers requests.
        #
        # This, of course, needs to be replaced with a proper connection
        # termination handshake.
        #raise_NotImplementedError("No implementation of shutdown present. Read the comments & code of client_socket.py.")


    def close(self):
        """Cleans up any internal state by at least destroying the instance of
        the lossy layer in use. Also called by the destructor of this socket.

        Do not confuse with shutdown, which disconnects the connection.
        close destroys *local* resources, and should only be called *after*
        shutdown.

        Probably does not need to be modified, but if you do, be careful to
        gate all calls to destroy resources with checks that destruction is
        valid at this point -- this method will also be called by the
        destructor itself. The easiest way of doing this is shown by the
        existing code:
            1. check whether the reference to the resource is not None.
                2. if so, destroy the resource.
            3. set the reference to None.
        """
        logger.debug("close called")
        ll = getattr(self, "_lossy_layer", None)
        if ll != None:
            ll.destroy()
            self._lossy_layer = None


    def __del__(self):
        """Destructor. Do not modify."""
        logger.debug("__del__ called")
        self.close()
