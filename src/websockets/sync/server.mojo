# Code adapted from https://github.com/saviorand/lightbug_http/tree/feature/websocket/
# Thanks to @rd4com for the original code

from base64 import b64encode
from collections import Dict, InlineArray, List, Optional
from memory import UnsafePointer
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
from mojix.ctypes import c_void
from mojix.io_uring import SQE64, IoUringOp, IoUringSqeFlags
from mojix.net.socket import socket, bind, listen
from mojix.net.types import AddrFamily, SocketType, SocketAddrV4
from io_uring import IoUring
from io_uring.buf import BufRing
from io_uring.op import Accept, Read, Write

alias ACCEPT = 0
alias READ = 1
alias WRITE = 2
alias CLOSE = 3  # For handling connection closing

# Configuration for io_uring
alias MAX_CONNECTIONS = 16
alias BACKLOG = 512
# alias MAX_MESSAGE_LEN = 16384  # Increased for WebSocket frames
alias MAX_MESSAGE_LEN = 2048  # Reduced because of compiler slow compilation (InlineArray meta-programming)
alias BUFFERS_COUNT = 16  # Must be power of 2
alias BUF_RING_SIZE = BUFFERS_COUNT
# Number of entries in the submission queue
alias SQ_ENTRIES = 128

alias ConnHandler = fn (conn: WSConnection, data: Span[Byte]) raises -> None


@value
@register_passable("trivial")
struct ConnInfo(Writable):
    var fd: Int32
    var type: UInt16
    var bid: UInt16  # Buffer ID (now UInt16 to match the echoserver example)
    var protocol_id: UInt16  # ID to track which protocol instance this is associated with

    fn __init__(
        out self, fd: Int32, type: UInt16, bid: UInt16 = 0, protocol_id: UInt16 = 0
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
            bid=UInt16(value & 0xFFFF),
        )

    fn write_to[W: Writer](self, mut writer: W) -> None:
        type_str = (
            "ACCEPT" if self.type
            == ACCEPT else "READ" if self.type
            == READ else "WRITE" if self.type
            == WRITE else "CLOSE"
        )
        writer.write(
            "ConnInfo(fd: ",
            self.fd,
            ", type:",
            type_str,
            ", bid:",
            self.bid,
            ", protocol_id:",
            self.protocol_id,
            ")",
        )


# Helper functions for buffer operations
fn submit_read_with_buffer_select(
    fd: Int32, mut ring: IoUring, mut buf_ring: BufRing, protocol_id: UInt16 = 0
) raises:
    """Submit a read operation with BUFFER_SELECT flag to have the kernel select a buffer.
    This is the proper way to use buffer rings - let the kernel pick a buffer from the
    ring rather than selecting ourselves."""

    sq = ring.sq()
    if sq:
        read_conn = ConnInfo(fd=fd, type=READ, protocol_id=protocol_id)
        logger.debug("Setting up read with buffer select for fd:", fd)

        # Setup a Read operation with proper buffer select flags
        var client_fd = Fd(unsafe_fd=fd)
        var buf_ring_ptr = buf_ring[]

        # We only need the buffer pointer for the size, kernel will select which buffer to use
        var buffer_ptr = buf_ring_ptr.unsafe_buf(
            index=0, len=UInt32(MAX_MESSAGE_LEN)
        ).buf_ptr

        # Get an SQE and set the BUFFER_SELECT flag
        var sqe = sq.__next__()
        sqe.flags |= IoUringSqeFlags.BUFFER_SELECT

        # Create read operation with a new SQE, just like in the working echoserver example
        _ = Read(
            sq.__next__(),  # Use a fresh SQE here, not the one we set flags on
            client_fd,
            buffer_ptr,
            UInt(MAX_MESSAGE_LEN),
        ).user_data(read_conn.to_int())


fn submit_write_with_buffer(
    fd: Int32,
    buf_ptr: UnsafePointer[c_void],
    bytes_count: Int,
    mut ring: IoUring,
    protocol_id: UInt16 = 0,
) raises:
    """Handle read completion by submitting a write with the provided buffer pointer.
    The buffer will be recycled when the Buf object goes out of scope in the caller."""

    sq = ring.sq()
    if sq:
        write_conn = ConnInfo(fd=fd, type=WRITE, protocol_id=protocol_id)
        logger.debug("Setting up write with fd:", write_conn.fd)

        # Submit write with user-provided buffer
        _ = Write(
            sq.__next__(), Fd(unsafe_fd=write_conn.fd), buf_ptr, UInt(bytes_count)
        ).user_data(write_conn.to_int())


struct WSConnection:
    """
    A connection object that represents a WebSocket connection.
    """

    var fd: Fd
    var protocol_id: UInt16
    var ring: UnsafePointer[IoUring]
    var buf_ring: UnsafePointer[BufRing]
    var server: UnsafePointer[Server]

    fn __init__(
        out self,
        fd: Int,
        protocol_id: UInt16,
        owned ring: UnsafePointer[IoUring],
        owned buf_ring: UnsafePointer[BufRing],
        owned server: UnsafePointer[Server],
    ):
        self.fd = Fd(unsafe_fd=fd)
        self.protocol_id = protocol_id
        self.ring = ring
        self.buf_ring = buf_ring
        self.server = server

    fn send_text(self, message: String) raises:
        # Find the protocol
        var protocol_ptr = UnsafePointer[ServerProtocol].address_of(
            self.server[].protocols[self.protocol_id]
        )

        # Prepare the message
        send_text(protocol_ptr[], str_to_bytes(message))
        var data_to_send = protocol_ptr[].data_to_send()

        if len(data_to_send) == 0:
            logger.debug("No data to send")
            return

        # Allocate a heap buffer that will stay alive until the operation completes
        var heap_buffer = UnsafePointer[Int8].alloc(MAX_MESSAGE_LEN)

        # Copy data to the heap buffer
        for i in range(len(data_to_send)):
            if i < MAX_MESSAGE_LEN:
                heap_buffer[i] = Int8(data_to_send[i])

        # Use direct write_with_buffer helper that handles submission
        submit_write_with_buffer(
            self.fd.unsafe_fd(),
            UnsafePointer[c_void](heap_buffer),
            len(data_to_send),
            self.ring[],
            self.protocol_id,
        )

        # Submit the operation
        var submitted = self.ring[].submit_and_wait(wait_nr=1)
        logger.debug("send_text submitted operations:", submitted)

        # Process any completions to ensure our write is done
        for cqe in self.ring[].cq(wait_nr=0):
            logger.debug("Processed completion in send_text")

        # Now it's safe to free the buffer
        heap_buffer.free()

        # Set up a read to receive the next message
        submit_read_with_buffer_select(
            self.fd.unsafe_fd(), self.ring[], self.buf_ring[], self.protocol_id
        )

    fn send_binary(self, message: Bytes) raises:
        # Find the protocol
        var protocol_ptr = UnsafePointer[ServerProtocol].address_of(
            self.server[].protocols[self.protocol_id]
        )

        # Prepare the message
        send_binary(protocol_ptr[], message)
        var data_to_send = protocol_ptr[].data_to_send()

        if len(data_to_send) == 0:
            logger.debug("No binary data to send")
            return

        # Allocate a heap buffer that will stay alive until the operation completes
        var heap_buffer = UnsafePointer[Int8].alloc(MAX_MESSAGE_LEN)

        # Copy data to the heap buffer
        for i in range(len(data_to_send)):
            if i < MAX_MESSAGE_LEN:
                heap_buffer[i] = Int8(data_to_send[i])

        # Use direct write_with_buffer helper that handles submission
        submit_write_with_buffer(
            self.fd.unsafe_fd(),
            UnsafePointer[c_void](heap_buffer),
            len(data_to_send),
            self.ring[],
            self.protocol_id,
        )

        # Submit the operation
        var submitted = self.ring[].submit_and_wait(wait_nr=1)
        logger.debug("send_binary submitted operations:", submitted)

        # Process any completions to ensure our write is done
        for cqe in self.ring[].cq(wait_nr=0):
            logger.debug("Processed completion in send_binary")

        # Now it's safe to free the buffer
        heap_buffer.free()

        # Set up a read to receive the next message
        submit_read_with_buffer_select(
            self.fd.unsafe_fd(), self.ring[], self.buf_ring[], self.protocol_id
        )

    fn close(self) raises -> None:
        # Just close the file descriptor
        var native_fd = self.fd.unsafe_fd()
        libc_close(native_fd)


struct Server[
    handler: ConnHandler,
]:
    """
    A Mojo-based WebSocket server that accepts incoming connections using io_uring for concurrency.

    Parameters:
        handler: ConnHandler - A function that handles incoming HTTP requests.
    """

    # TODO: add an error_handler to the constructor

    var host: String
    var port: Int
    var max_request_body_size: Int

    # io_uring related fields
    var ring: IoUring
    var buf_ring: BufRing
    var protocols: List[ServerProtocol]
    var active_connections: Int
    var running: Bool

    fn __moveinit__(out self, owned other: Self):
        self.host = other.host
        self.port = other.port
        self.max_request_body_size = other.max_request_body_size
        self.ln = other.ln^

    fn __copyinit__(out self, other: Self):
        self.host = other.host
        self.port = other.port
        self.max_request_body_size = other.max_request_body_size
        self.ln = other.ln

    fn __init__(
        out self,
        host: String,
        port: Int,
        max_request_body_size: Int = DEFAULT_MAX_REQUEST_BODY_SIZE,
    ) raises:
        """
        Initialize a new server.

        Args:
            host: String - The address to listen on.
            port: Int - The port to listen on.
            max_request_body_size: Int - The maximum size of the request body.

        Raises:
            If there is an error while initializing the server.
        """
        self.host = host
        self.port = port
        self.max_request_body_size = max_request_body_size

        # Initialize io_uring instance
        self.ring = IoUring(sq_entries=SQ_ENTRIES)

        # Create buffer ring for efficient memory management
        logger.info(
            "Initializing buffer ring with",
            BUFFERS_COUNT,
            "entries of size",
            MAX_MESSAGE_LEN,
        )
        # Use buffer group ID 0 as that's what kernel expects by default
        self.buf_ring = self.ring.create_buf_ring(
            bgid=0,  # Buffer group ID (must be consistent with Recv operation)
            entries=BUFFERS_COUNT,
            entry_size=MAX_MESSAGE_LEN,
        )

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

        # Clean up buf_ring properly
        # self.ring.unsafe_delete_buf_ring(self.buf_ring^)

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
            # This call is critical for the event loop to work correctly
            var submitted = self.ring.submit_and_wait(wait_nr=1)

            logger.debug("Submitted io_uring operations:", submitted)

            if submitted < 0:
                logger.error("Error submitting io_uring operations:", submitted)
                break

            # Process all available completions - important to process ALL events
            for cqe in self.ring.cq(wait_nr=0):
                var res = cqe.res
                var user_data = cqe.user_data
                var flags = cqe.flags  # Important for buffer handling

                var conn = ConnInfo.from_int(user_data)

                # Use more detailed error reporting like in the working echoserver
                if res < 0:
                    logger.error(
                        "Error:", res, "on operation type:", conn.type, "fd:", conn.fd
                    )
                    continue

                logger.debug("Completion result:", res, "for conn:", conn)

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

                    # Add read for the new connection using buffer select
                    submit_read_with_buffer_select(
                        client_fd.unsafe_fd(), self.ring, self.buf_ring, protocol_id
                    )

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
                    else:
                        # Get buffer from completion flags
                        var bytes_read = Int(res)
                        var flags = cqe.flags

                        # Extract buffer index from completion flags
                        # The kernel provides buffer index and other info in the flags field
                        var buffer_idx = BufRing.flags_to_index(flags)
                        logger.debug(
                            "Read completion (bytes:",
                            bytes_read,
                            ", buffer_idx:",
                            buffer_idx,
                            ")",
                        )

                        # Need to make sure buffer_idx is valid - it should be < BUFFERS_COUNT
                        if buffer_idx >= BUFFERS_COUNT:
                            logger.error("Invalid buffer index:", buffer_idx)
                            buffer_idx = 0

                        # Get a buffer handle with the correct index and size
                        # Using unsafe_buf ensures the buffer is properly tracked by the kernel
                        var buf_ring_ptr = self.buf_ring[]
                        var buffer = buf_ring_ptr.unsafe_buf(
                            index=buffer_idx, len=UInt32(bytes_read)
                        )
                        var buffer_ptr = UnsafePointer[Int8](buffer.buf_ptr)

                        # Create a Bytes object from the buffer
                        var data = Bytes(capacity=bytes_read)
                        for i in range(bytes_read):
                            data.append(UInt8(buffer_ptr[i]))

                        # Process the data with the protocol
                        if conn.protocol_id < len(self.protocols):
                            var protocol_ptr = UnsafePointer[ServerProtocol].address_of(
                                self.protocols[conn.protocol_id]
                            )

                            # Send data to protocol
                            receive_data(protocol_ptr[], data)

                            # Check for parser exceptions
                            if protocol_ptr[].get_parser_exc():
                                logger.error(
                                    String(protocol_ptr[].get_parser_exc().value())
                                )

                                # Close the connection
                                libc_close(conn.fd)
                                self.active_connections -= 1

                                logger.info(
                                    "Connection closed (active:",
                                    self.active_connections,
                                    ")",
                                )

                                # Mark protocol as inactive
                                protocol_ptr[].set_inactive()

                                # Buffer is automatically recycled when it goes out of scope
                                continue

                            # Handle connection state
                            if protocol_ptr[].get_state() == CONNECTING:
                                # WebSocket handshake
                                logger.debug("Handling WebSocket handshake")
                                var events_list = protocol_ptr[].events_received()
                                if len(events_list) > 0:
                                    var request: HTTPRequest = events_list[0][
                                        HTTPRequest
                                    ]
                                    var response = protocol_ptr[].accept(request)

                                    if protocol_ptr[].get_handshake_exc():
                                        logger.error(
                                            String(
                                                protocol_ptr[]
                                                .get_handshake_exc()
                                                .value()
                                            )
                                        )

                                        # Close the connection
                                        libc_close(conn.fd)
                                        self.active_connections -= 1

                                        # Mark protocol as inactive
                                        protocol_ptr[].set_inactive()

                                        # Buffer is automatically recycled when it goes out of scope
                                        continue

                                    logger.debug("Sending handshake response")
                                    protocol_ptr[].send_response(response)
                                    var data_to_send = protocol_ptr[].data_to_send()

                                    logger.debug(
                                        "Have handshake data to send:",
                                        len(data_to_send),
                                    )

                                    # Allocate a heap buffer that will stay alive until the operation completes
                                    var heap_buffer = UnsafePointer[Int8].alloc(
                                        MAX_MESSAGE_LEN
                                    )

                                    # Copy data to the heap buffer
                                    for i in range(len(data_to_send)):
                                        if i < MAX_MESSAGE_LEN:
                                            heap_buffer[i] = Int8(data_to_send[i])

                                    # Use write_with_buffer helper that handles submission
                                    submit_write_with_buffer(
                                        conn.fd,
                                        UnsafePointer[c_void](heap_buffer),
                                        len(data_to_send),
                                        self.ring,
                                        conn.protocol_id,
                                    )

                                    # Submit and wait for the operation to complete
                                    var submitted = self.ring.submit_and_wait(wait_nr=1)
                                    logger.debug(
                                        "Handshake submitted operations:", submitted
                                    )

                                    # Process completions to ensure our write is done
                                    for cqe in self.ring.cq(wait_nr=0):
                                        logger.debug(
                                            "Processed completion in handshake"
                                        )

                                    # Now it's safe to free the buffer
                                    heap_buffer.free()

                                    # Post a new read for the connection after handshake
                                    logger.info(
                                        "Setting up read after handshake for fd:",
                                        conn.fd,
                                    )
                                    submit_read_with_buffer_select(
                                        conn.fd,
                                        self.ring,
                                        self.buf_ring,
                                        conn.protocol_id,
                                    )
                            else:
                                # Handle WebSocket frames
                                logger.debug("Handling WebSocket frame")
                                self.handle_websocket_frame(conn)

                            # Buffer is automatically recycled when it goes out of scope at the end of this block

                # Handle write completion
                elif conn.type == WRITE:
                    logger.debug(
                        "Write completion (fd:",
                        conn.fd,
                        ", protocol_id:",
                        conn.protocol_id,
                        ")",
                    )

                    # Post a new read for the connection using BUFFER_SELECT
                    # This is critical for the WebSocket server's message handling pattern
                    logger.info(
                        "Setting up next read after write completion for fd:", conn.fd
                    )
                    submit_read_with_buffer_select(
                        conn.fd, self.ring, self.buf_ring, conn.protocol_id
                    )

    fn handle_websocket_frame(mut self, conn: ConnInfo) raises -> None:
        """
        Handle incoming WebSocket frames.

        Args:
            conn: ConnInfo - Connection information.
        """
        if conn.protocol_id >= len(self.protocols):
            return

        var protocol_ptr = UnsafePointer[ServerProtocol].address_of(
            self.protocols[conn.protocol_id]
        )
        var events_received = protocol_ptr[].events_received()

        # Create a WSConnection for the handler
        var wsconn = WSConnection(
            Int(conn.fd),
            conn.protocol_id,
            UnsafePointer.address_of(self.ring),
            UnsafePointer.address_of(self.buf_ring),
            UnsafePointer.address_of(self),
        )

        for event_ref in events_received:
            var event = event_ref[]
            if event.isa[Frame]() and event[Frame].is_data():
                var data_received = event[Frame].data

                # Call the handler
                self.handler(wsconn, data_received)

        var data_to_send = protocol_ptr[].data_to_send()
        if len(data_to_send) > 0:
            logger.debug("WebSocket frame handler has data to send:", len(data_to_send))

            # Allocate a heap buffer that will stay alive until the operation completes
            var heap_buffer = UnsafePointer[Int8].alloc(MAX_MESSAGE_LEN)

            # Copy data to the heap buffer
            for i in range(len(data_to_send)):
                if i < MAX_MESSAGE_LEN:
                    heap_buffer[i] = Int8(data_to_send[i])

            # Use direct write_with_buffer helper that handles submission
            submit_write_with_buffer(
                conn.fd,
                UnsafePointer[c_void](heap_buffer),
                len(data_to_send),
                self.ring,
                conn.protocol_id,
            )

            # Submit the operation
            var submitted = self.ring.submit_and_wait(wait_nr=1)
            logger.debug("handle_websocket_frame submitted operations:", submitted)

            # Process any completions to ensure our write is done
            for cqe in self.ring.cq(wait_nr=0):
                logger.debug("Processed completion in handle_websocket_frame")

            # Now it's safe to free the buffer
            heap_buffer.free()

        # IMPORTANT: Post a new read for this connection - this is critical for the next message
        logger.info(
            "Setting up follow-up read in WebSocket frame handler for fd:", conn.fd
        )
        submit_read_with_buffer_select(
            conn.fd, self.ring, self.buf_ring, conn.protocol_id
        )

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


fn serve[handler: ConnHandler](host: String, port: Int) raises -> Server[handler]:
    """
    Serve WebSocket requests concurrently using io_uring.

    Args:
        host: String - The address to listen on.
        port: Int - The port to listen on.

    Parameters:
        handler: ConnHandler - A function that handles incoming HTTP requests.

    Returns:
        Server - A server object that can be used to serve requests.

    Raises:
        If there is an error while serving requests.

    Usage:
        with serve[handler](host, port) as server:
            server.serve_forever()
    .
    """
    return Server[handler](host, port)
