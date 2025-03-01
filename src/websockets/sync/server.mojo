# Code adapted from https://github.com/saviorand/lightbug_http/tree/feature/websocket/
# Thanks to @rd4com for the original code

from base64 import b64encode
from collections import Dict, InlineArray, List, Optional
from memory import UnsafePointer
from python import Python, PythonObject
from time import sleep

from websockets.libc import c_int, close as libc_close

from websockets.aliases import (
    Bytes,
    DEFAULT_BUFFER_SIZE,
    DEFAULT_MAX_REQUEST_BODY_SIZE,
    MAGIC_CONSTANT,
)
from websockets.frames import Frame
from websockets.http import Header, Headers, HTTPRequest, HTTPResponse, encode
from websockets.logger import logger
from websockets.net import ListenConfig, TCPConnection, TCPListener
from websockets.protocol import CONNECTING, SERVER
from websockets.protocol.base import receive_data, receive_eof, send_text, send_binary
from websockets.protocol.server import ServerProtocol
from websockets.protocol.client import ClientProtocol
from websockets.utils.bytes import str_to_bytes

from mojix.fd import Fd
from mojix.io_uring import SQE64
from mojix.net.socket import socket, bind, listen
from mojix.net.types import AddrFamily, SocketType, SocketAddrV4
from io_uring import IoUring
from io_uring.op import Accept, Read, Write

alias ACCEPT = 0
alias READ = 1
alias WRITE = 2
alias CLOSE = 3  # For handling connection closing

# Configuration for io_uring
# alias MAX_CONNECTIONS = 16
alias MAX_CONNECTIONS = 8
alias BACKLOG = 512
# alias MAX_MESSAGE_LEN = 16384  # Increased for WebSocket frames
alias MAX_MESSAGE_LEN = 1024
# alias BUFFERS_COUNT = 16  # Must be power of 2
alias BUFFERS_COUNT = 4  # Must be power of 2
alias BUF_RING_SIZE = BUFFERS_COUNT
# Number of entries in the submission queue
# alias SQ_ENTRIES = 128
alias SQ_ENTRIES = 24

alias ConnHandler = fn (conn: WSConnection, data: Bytes) raises -> None


@value
struct ConnInfo:
    var fd: Int32
    var type: UInt16
    var bid: UInt32  # Buffer ID
    var protocol_id: UInt16  # ID to track which protocol instance this is associated with

    fn __init__(
        out self, fd: Int32, type: UInt16, bid: UInt32 = 0, protocol_id: UInt16 = 0
    ):
        self.fd = fd
        self.type = type
        self.bid = bid
        self.protocol_id = protocol_id

    fn to_int(self) -> UInt64:
        """Pack ConnInfo into a 64-bit integer for user_data."""
        return (
            (UInt64(self.fd) << 32)
            | (UInt64(self.type) << 24)
            | (UInt64(self.protocol_id) << 16)
            | UInt64(self.bid)
        )

    @staticmethod
    fn from_int(value: UInt64) -> Self:
        """Unpack ConnInfo from a 64-bit integer."""
        return Self(
            fd=Int32((value >> 32) & 0xFFFFFFFF),
            type=UInt16((value >> 24) & 0xFF),
            protocol_id=UInt16((value >> 16) & 0xFF),
            bid=UInt32(value & 0xFFFF),
        )


struct BufferMemory:
    """Manages the buffer memory for the server."""

    var _data: InlineArray[Int8, MAX_MESSAGE_LEN * BUFFERS_COUNT]
    var _buffer_avail: InlineArray[Bool, BUFFERS_COUNT]  # Track buffer availability

    fn __init__(out self):
        """Initialize the buffer memory."""
        logger.debug("Initializing BufferMemory with direct buffers")
        self._data = InlineArray[Int8, MAX_MESSAGE_LEN * BUFFERS_COUNT](fill=0)
        self._buffer_avail = InlineArray[Bool, BUFFERS_COUNT](
            fill=True
        )  # All buffers start as available

    fn get_buffer_pointer(self, idx: Int) -> UnsafePointer[Int8]:
        """Get a pointer to a specific buffer."""
        return self._data.unsafe_ptr() + (idx * MAX_MESSAGE_LEN)

    fn get_available_buffer(mut self) -> (Int, UnsafePointer[Int8]):
        """Get an available buffer."""
        # Find an available buffer
        for i in range(BUFFERS_COUNT):
            if self._buffer_avail[i]:
                self._buffer_avail[i] = False  # Mark as in use
                return (i, self.get_buffer_pointer(i))

        # If all buffers are in use, just return the first one
        logger.error("All buffers in use, recycling buffer 0")
        return (0, self.get_buffer_pointer(0))

    fn mark_buffer_available(mut self, idx: Int):
        """Mark a buffer as available."""
        self._buffer_avail[idx] = True


struct WSConnection:
    """
    A connection object that represents a WebSocket connection.
    """

    var fd: Fd
    var protocol_id: UInt16
    var buffer_memory: UnsafePointer[BufferMemory]
    var ring: UnsafePointer[IoUring]
    var server: UnsafePointer[Server]

    fn __init__(
        out self,
        fd: Int,
        protocol_id: UInt16,
        owned buffer_memory: UnsafePointer[BufferMemory],
        owned ring: UnsafePointer[IoUring],
        owned server: UnsafePointer[Server],
    ):
        self.fd = Fd(unsafe_fd=fd)
        self.protocol_id = protocol_id
        self.buffer_memory = buffer_memory
        self.ring = ring
        self.server = server

    fn send_text(self, message: String) raises:
        # Find the protocol
        var protocol_ref = self.server[].protocols[self.protocol_id]

        # Prepare the message
        send_text(protocol_ref, str_to_bytes(message))
        var data_to_send = protocol_ref.data_to_send()

        # Use io_uring to write the data
        var sq = self.ring[].sq()
        if sq:
            # We need to copy the data because we can't guarantee when io_uring will use it
            var buffer_idx = Int(self.buffer_memory[].get_available_buffer()[0])
            var buffer_ptr = self.buffer_memory[].get_buffer_pointer(buffer_idx)

            # Copy data to the buffer
            for i in range(len(data_to_send)):
                buffer_ptr[i] = Int8(data_to_send[i])

            var write_conn = ConnInfo(
                fd=self.fd.unsafe_fd(),
                type=WRITE,
                bid=UInt32(buffer_idx),
                protocol_id=self.protocol_id,
            )
            _ = Write[type=SQE64, origin = __origin_of(sq)](
                sq.__next__(), self.fd, buffer_ptr, UInt(len(data_to_send))
            ).user_data(write_conn.to_int())

            # Submit operations
            _ = self.ring[].submit_and_wait(wait_nr=1)

    fn send_binary(self, message: Bytes) raises:
        # Find the protocol
        var protocol_ref = self.server[].protocols[self.protocol_id]

        # Prepare the message
        send_binary(protocol_ref, message)
        var data_to_send = protocol_ref.data_to_send()

        # Use io_uring to write the data
        var sq = self.ring[].sq()
        if sq:
            # We need to copy the data because we can't guarantee when io_uring will use it
            var buffer_idx = Int(self.buffer_memory[].get_available_buffer()[0])
            var buffer_ptr = self.buffer_memory[].get_buffer_pointer(buffer_idx)

            # Copy data to the buffer
            for i in range(len(data_to_send)):
                buffer_ptr[i] = Int8(data_to_send[i])

            var write_conn = ConnInfo(
                fd=self.fd.unsafe_fd(),
                type=WRITE,
                bid=UInt32(buffer_idx),
                protocol_id=self.protocol_id,
            )
            _ = Write[type=SQE64, origin = __origin_of(sq)](
                sq.__next__(), self.fd, buffer_ptr, UInt(len(data_to_send))
            ).user_data(write_conn.to_int())

            # Submit operations
            _ = self.ring[].submit_and_wait(wait_nr=1)

    fn close(self) raises -> None:
        # Just close the file descriptor
        var native_fd = self.fd.unsafe_fd()
        libc_close(native_fd)


struct Server:
    """
    A Mojo-based WebSocket server that accepts incoming connections using io_uring for concurrency.
    """

    var host: String
    var port: Int
    var handler: ConnHandler
    var max_request_body_size: Int

    # io_uring related fields
    var ring: IoUring
    var buffer_memory: BufferMemory
    var protocols: List[ServerProtocol]
    var active_connections: Int
    var running: Bool

    fn __init__(
        out self,
        host: String,
        port: Int,
        handler: ConnHandler,
        max_request_body_size: Int = DEFAULT_MAX_REQUEST_BODY_SIZE,
    ) raises:
        """
        Initialize a new server.

        Args:
            host: String - The address to listen on.
            port: Int - The port to listen on.
            handler: ConnHandler - An object that handles incoming WebSocket messages.
            max_request_body_size: Int - The maximum size of the request body.

        Raises:
            If there is an error while initializing the server.
        """
        self.host = host
        self.port = port
        self.handler = handler
        self.max_request_body_size = max_request_body_size

        # Initialize io_uring instance
        self.ring = IoUring[](sq_entries=SQ_ENTRIES)

        # Initialize buffer memory
        self.buffer_memory = BufferMemory()

        # Initialize protocol list
        self.protocols = List[ServerProtocol]()
        for _ in range(MAX_CONNECTIONS):
            self.protocols.append(ServerProtocol())

        self.active_connections = 0
        self.running = False

    fn __enter__(self) raises -> Self:
        """
        Context manager entry point, called by the serve() function.

        Usage:
            with serve(handler, host, port) as server:
                server.serve_forever()
        """
        return Self(self.host, self.port, self.handler, self.max_request_body_size)

    fn __exit__(
        mut self,
    ) raises -> None:
        """
        Context manager exit point, called by the serve() function which closes the server.
        """
        self.shutdown()

    # ===-------------------------------------------------------------------=== #
    # Methods
    # ===-------------------------------------------------------------------=== #

    fn serve_forever(mut self) raises:
        """
        Listen for incoming connections and serve WebSocket requests concurrently using io_uring.
        """
        self.running = True

        # Setup listener socket
        var listener_fd = socket(AddrFamily.INET, SocketType.STREAM)
        var ip_parts = self.host.split(".")

        # Parse the IP address
        var a: UInt8 = 0
        var b: UInt8 = 0
        var c: UInt8 = 0
        var d: UInt8 = 0

        # Handle different host values
        if self.host == "localhost" or self.host == "127.0.0.1":
            a = 127
            b = 0
            c = 0
            d = 1
        elif len(ip_parts) == 4:
            try:
                a = UInt8(Int(ip_parts[0]))
                b = UInt8(Int(ip_parts[1]))
                c = UInt8(Int(ip_parts[2]))
                d = UInt8(Int(ip_parts[3]))
            except:
                a = 0
                b = 0
                c = 0
                d = 0

        bind(listener_fd, SocketAddrV4(a, b, c, d, port=UInt16(self.port)))
        listen(listener_fd, backlog=BACKLOG)
        logger.info("WebSocket server listening on", self.host, "port", self.port)

        # Add initial accept
        var sq = self.ring.sq()
        if sq:
            var conn = ConnInfo(fd=Int32(listener_fd.unsafe_fd()), type=ACCEPT)
            _ = Accept(sq.__next__(), listener_fd).user_data(conn.to_int())

        # Main event loop
        while self.running:
            # Submit and wait for at least 1 completion
            var submitted = self.ring.submit_and_wait(wait_nr=1)

            if submitted < 0:
                logger.error("Error submitting io_uring operations")
                break

            # Process completions
            for cqe in self.ring.cq(wait_nr=0):
                var res = cqe.res
                var user_data = cqe.user_data

                if res < 0:
                    logger.error("Error in completion:", res)
                    continue

                var conn = ConnInfo.from_int(user_data)

                # Handle accept completion
                if conn.type == ACCEPT:
                    # New connection
                    var client_fd = Fd(unsafe_fd=res)

                    # Find an available protocol slot
                    var protocol_id: UInt16 = 0
                    for i in range(MAX_CONNECTIONS):
                        if (
                            i < len(self.protocols)
                            and not self.protocols[i].is_active()
                        ):
                            protocol_id = UInt16(i)
                            break

                    self.active_connections += 1
                    logger.info(
                        "New connection (active:",
                        self.active_connections,
                        ", protocol_id:",
                        protocol_id,
                        ")",
                    )

                    # Reset the protocol for this connection
                    if protocol_id < len(self.protocols):
                        self.protocols[protocol_id] = ServerProtocol()
                        self.protocols[protocol_id].set_active()
                    else:
                        self.protocols.append(ServerProtocol())
                        self.protocols[protocol_id].set_active()

                    # Add read for the new connection
                    sq = self.ring.sq()
                    if sq:
                        # Get available buffer
                        var result = self.buffer_memory.get_available_buffer()
                        var buf_idx = result[0]
                        var buf_ptr = result[1]
                        read_conn = ConnInfo(
                            fd=client_fd.unsafe_fd(),
                            type=READ,
                            bid=UInt32(buf_idx),
                            protocol_id=protocol_id,
                        )
                        _ = Read[type=SQE64, origin = __origin_of(sq)](
                            sq.__next__(), client_fd, buf_ptr, UInt(MAX_MESSAGE_LEN)
                        ).user_data(read_conn.to_int())

                    # Re-add accept
                    sq = self.ring.sq()
                    if sq:
                        accept_conn = ConnInfo(fd=listener_fd.unsafe_fd(), type=ACCEPT)
                        _ = Accept(sq.__next__(), listener_fd).user_data(
                            accept_conn.to_int()
                        )

                # Handle read completion
                elif conn.type == READ:
                    if res <= 0:
                        # Connection closed or error
                        self.active_connections -= 1
                        logger.info(
                            "Connection closed (active:", self.active_connections, ")"
                        )

                        # Mark the protocol as inactive
                        if conn.protocol_id < len(self.protocols):
                            self.protocols[conn.protocol_id].set_inactive()

                        # Free the buffer
                        self.buffer_memory.mark_buffer_available(Int(conn.bid))
                    else:
                        # Get buffer info
                        var buffer_idx = Int(conn.bid)
                        var buffer_ptr = self.buffer_memory.get_buffer_pointer(
                            buffer_idx
                        )
                        var bytes_read = Int(res)

                        # Create a Bytes object from the buffer
                        var data = Bytes(capacity=bytes_read)
                        for i in range(bytes_read):
                            data.append(UInt8(buffer_ptr[i]))

                        # Process the data with the protocol
                        if conn.protocol_id < len(self.protocols):
                            var protocol = self.protocols[conn.protocol_id]

                            # Send data to protocol
                            receive_data(protocol, data)

                            # Check for parser exceptions
                            if protocol.get_parser_exc():
                                logger.error(String(protocol.get_parser_exc().value()))

                                # Close the connection
                                libc_close(conn.fd)
                                self.active_connections -= 1

                                # Mark protocol as inactive
                                protocol.set_inactive()

                                # Free the buffer
                                self.buffer_memory.mark_buffer_available(buffer_idx)
                                continue

                            # Handle connection state
                            if protocol.get_state() == CONNECTING:
                                # WebSocket handshake
                                logger.debug("Handling WebSocket handshake")
                                var events_list = protocol.events_received()
                                if len(events_list) > 0:
                                    var request: HTTPRequest = events_list[0][
                                        HTTPRequest
                                    ]
                                    var response = protocol.accept(request)

                                    if protocol.get_handshake_exc():
                                        logger.error(
                                            String(protocol.get_handshake_exc().value())
                                        )

                                        # Close the connection
                                        libc_close(conn.fd)
                                        self.active_connections -= 1

                                        # Mark protocol as inactive
                                        protocol.set_inactive()

                                        # Free the buffer
                                        self.buffer_memory.mark_buffer_available(
                                            buffer_idx
                                        )
                                        continue

                                    logger.debug("Sending handshake response")
                                    protocol.send_response(response)
                                    var data_to_send = protocol.data_to_send()

                                    # Use io_uring to write the handshake response
                                    sq = self.ring.sq()
                                    if sq:
                                        # Copy data to a fresh buffer
                                        var new_buffer_idx = Int(
                                            self.buffer_memory.get_available_buffer()[0]
                                        )
                                        var new_buffer_ptr = self.buffer_memory.get_buffer_pointer(
                                            new_buffer_idx
                                        )

                                        # Copy the data
                                        for i in range(len(data_to_send)):
                                            new_buffer_ptr[i] = Int8(data_to_send[i])

                                        # Send handshake response
                                        write_conn = ConnInfo(
                                            fd=conn.fd,
                                            type=WRITE,
                                            bid=UInt32(new_buffer_idx),
                                            protocol_id=conn.protocol_id,
                                        )
                                        _ = Write[type=SQE64, origin = __origin_of(sq)](
                                            sq.__next__(),
                                            Fd(unsafe_fd=conn.fd),
                                            new_buffer_ptr,
                                            UInt(len(data_to_send)),
                                        ).user_data(write_conn.to_int())
                            else:
                                # Handle WebSocket frames
                                self.handle_websocket_frame(conn, buffer_idx)

                # Handle write completion
                elif conn.type == WRITE:
                    logger.debug("Write completion (buffer_idx:", conn.bid, ")")

                    # Free the buffer
                    self.buffer_memory.mark_buffer_available(Int(conn.bid))

                    # Post a new read for the connection
                    sq = self.ring.sq()
                    if sq:
                        # Get available buffer
                        var result = self.buffer_memory.get_available_buffer()
                        var buf_idx = result[0]
                        var buf_ptr = result[1]
                        read_conn = ConnInfo(
                            fd=conn.fd,
                            type=READ,
                            bid=UInt32(buf_idx),
                            protocol_id=conn.protocol_id,
                        )
                        _ = Read[type=SQE64, origin = __origin_of(sq)](
                            sq.__next__(),
                            Fd(unsafe_fd=conn.fd),
                            buf_ptr,
                            UInt(MAX_MESSAGE_LEN),
                        ).user_data(read_conn.to_int())

    fn handle_websocket_frame(mut self, conn: ConnInfo, buffer_idx: Int) raises -> None:
        """
        Handle incoming WebSocket frames.

        Args:
            conn: ConnInfo - Connection information.
            buffer_idx: Int - Buffer index.
        """
        if conn.protocol_id >= len(self.protocols):
            return

        var protocol = self.protocols[conn.protocol_id]
        var events_received = protocol.events_received()

        for event_ref in events_received:
            var event = event_ref[]
            if event.isa[Frame]() and event[Frame].is_data():
                var data_received = event[Frame].data

                # Create an WSConnection for the handler
                var wsconn = WSConnection(
                    Int(conn.fd),
                    conn.protocol_id,
                    UnsafePointer.address_of(self.buffer_memory),
                    UnsafePointer.address_of(self.ring),
                    UnsafePointer.address_of(self),
                )

                # Call the handler
                self.handler(wsconn, data_received)

        var data_to_send = protocol.data_to_send()
        if len(data_to_send) > 0:
            # Use io_uring to write response
            var sq = self.ring.sq()
            if sq:
                # We need to copy the data
                var new_buffer_idx = Int(self.buffer_memory.get_available_buffer()[0])
                var new_buffer_ptr = self.buffer_memory.get_buffer_pointer(
                    new_buffer_idx
                )

                # Copy the data
                for i in range(len(data_to_send)):
                    new_buffer_ptr[i] = Int8(data_to_send[i])

                var write_conn = ConnInfo(
                    fd=conn.fd,
                    type=WRITE,
                    bid=UInt32(new_buffer_idx),
                    protocol_id=conn.protocol_id,
                )
                _ = Write[type=SQE64, origin = __origin_of(sq)](
                    sq.__next__(),
                    Fd(unsafe_fd=conn.fd),
                    new_buffer_ptr,
                    UInt(len(data_to_send)),
                ).user_data(write_conn.to_int())

    fn address(self) -> String:
        """
        Get the address of the server.
        """
        return String(self.host, ":", self.port)

    fn shutdown(mut self) raises -> None:
        """
        Shutdown the server.
        """
        self.running = False


fn serve(handler: ConnHandler, host: String, port: Int) raises -> Server:
    """
    Serve WebSocket requests concurrently using io_uring.

    Args:
        handler: ConnHandler - An object that handles incoming WebSocket messages.
        host: String - The address to listen on.
        port: Int - The port to listen on.

    Returns:
        Server - A server object that can be used to serve requests.

    Raises:
        If there is an error while serving requests.

    Usage:
        with serve(handler, host, port) as server:
            server.serve_forever()
    .
    """
    return Server(host, port, handler)
