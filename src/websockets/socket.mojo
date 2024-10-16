# Code adapted from: https://github.com/ericwb/mojo-socket/blob/main/socket/socket.mojo
# Thanks to @ericwb for the original code.

from sys import external_call
from sys import os_is_linux
from sys import os_is_windows
from memory import DTypePointer
from sys import sizeof


# Socket types
alias SOCK_STREAM = 1
alias SOCK_DGRAM = 2
alias SOCK_RAW = 3
alias SOCK_RDM = 4
alias SOCK_SEQPACKET = 5

# Protocols
alias AF_UNSPEC = 0
alias AF_UNIX = 1
alias AF_INET = 2
alias AF_INET6 = 10 if os_is_linux() else 23 if os_is_windows() else 30

# Socket domains
alias PF_INET = AF_INET
alias PF_INET6 = AF_INET6


# typedef __uint8_t       sa_family_t;
alias sa_family_t = UInt8

# typedef __uint32_t      in_addr_t;      /* base type for internet address */
alias in_addr_t = UInt32

# typedef __uint16_t      in_port_t;
alias in_port_t = UInt16


alias HOST_NAME_MAX = 255
alias INET_ADDRSTRLEN = 16


# struct sockaddr {
#     __uint8_t       sa_len;         /* total length */
#     sa_family_t     sa_family;      /* [XSI] address family */
#     char            sa_data[14];    /* [XSI] addr value */
# };
@value
@register_passable("trivial")
struct _c_sockaddr(Stringable):
    var sa_len: UInt8
    var sa_family: sa_family_t
    var sa_data: StaticTuple[UInt8, 14]

    fn __init__(inout self):
        self.sa_len = 0
        self.sa_family = 0
        self.sa_data = StaticTuple[UInt8, 14](0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)

    fn __str__(self) -> String:
        var res = String("{\n")
        res += "sa_len: " + str(self.sa_len) + ",\n"
        res += "sa_family: " + str(self.sa_family) + ",\n"
        return res + "}"


# struct in_addr {
#     in_addr_t s_addr;
# };
@value
struct _in_addr:
    var s_addr: in_addr_t

    fn __init__(inout self):
        self.s_addr = 0


# struct sockaddr_in {
#     __uint8_t       sin_len;
#     sa_family_t     sin_family;
#     in_port_t       sin_port;
#     struct  in_addr sin_addr;
#     char            sin_zero[8];
# };
@value
struct _c_sockaddr_in(Stringable):
    var sin_len: UInt8
    var sin_family: sa_family_t
    var sin_port: in_port_t
    var sin_addr: _in_addr
    var sin_zero: StaticTuple[Int8, 8]

    fn __init__(inout self):
        self.sin_len = 1 + 1 + 2 + 4 + 8
        self.sin_family = 0
        self.sin_port = 0
        self.sin_addr = _in_addr()
        self.sin_addr.s_addr = 0
        self.sin_zero = StaticTuple[Int8, 8](0, 0, 0, 0, 0, 0, 0, 0)

    fn __str__(self) -> String:
        var res = String("{\n")
        res += "sin_len: " + str(self.sin_len) + ",\n"
        res += "sin_family: " + str(self.sin_family) + ",\n"
        res += "sin_port: " + str(self.sin_port) + ",\n"
        res += "sin_addr: " + str(self.sin_addr.s_addr) + ",\n"
        return res + "}"


@value
struct Socket:
    """An initialized socket."""

    var family: UInt8
    var type: Int32
    var protocol: Int32
    var _sock_fd: Int32

    fn __init__(inout self):
        """Default constructor."""
        self.family = 0
        self.type = 0
        self.protocol = 0
        self._sock_fd = -1

    fn __init__(inout self, family: UInt8, type: Int32, protocol: Int32) raises:
        """Construct the socket.

        tcp_socket = Socket(AF_INET, SOCK_STREAM, 0)
        udp_socket = Socket(AF_INET, SOCK_DGRAM, 0)
        raw_socket = Socket(AF_INET, SOCK_RAW, protocol)

        Args:
            family: The socket family.
            type: The socket type.
            protocol: The socket protocol.
        """
        self.family = family
        self.type = type
        self.protocol = protocol
        var fd = external_call["socket", Int32](family, type, protocol)

        if fd == -1:
            var error_str = String("Socket.__init__()")
            _ = external_call["perror", UnsafePointer[NoneType]](error_str.unsafe_ptr())
            raise error_str

        self._sock_fd = fd.cast[DType.int32]()

    fn connect(inout self, hostname: String, port: UInt16) raises:
        var sockaddr_in = _c_sockaddr_in()
        sockaddr_in.sin_family = self.family
        sockaddr_in.sin_port = htons(port)
        sockaddr_in.sin_len = sizeof[_c_sockaddr_in]()
        sockaddr_in.sin_addr.s_addr = inet_pton(self.family, hostname)

        # int connect(int, const struct sockaddr *, socklen_t) __DARWIN_ALIAS_C(connect);
        # int connect(int socket, const struct sockaddr *address, socklen_t address_len)
        var err = external_call["connect", Int32](
            self._sock_fd,
            UnsafePointer.address_of(sockaddr_in),
            sockaddr_in.sin_len,
        )

        if err == -1:
            var error_str = String("Socket.connect()")
            _ = external_call["perror", UnsafePointer[NoneType]](error_str.unsafe_ptr())
            raise error_str

    fn fileno(inout self) -> Int32:
        return self._sock_fd

    # int getpeername(int socket, struct sockaddr *restrict address, socklen_t *restrict address_len);
    fn getpeername(inout self) raises -> Tuple[String, UInt16]:
        var sockaddr_in = _c_sockaddr_in()
        sockaddr_in.sin_family = self.family
        sockaddr_in.sin_len = sizeof[_c_sockaddr_in]()

        var err = external_call["getpeername", Int32](
            self._sock_fd,
            UnsafePointer.address_of(sockaddr_in),
            UnsafePointer.address_of(sockaddr_in.sin_len),
        )

        if err == -1:
            var error_str = String("Socket.getpeername()")
            _ = external_call["perror", UnsafePointer[NoneType]](error_str.unsafe_ptr())
            raise error_str

        var address = inet_ntop(AF_INET, sockaddr_in.sin_addr)

        return (address, sockaddr_in.sin_port)

    # int getsockname(int socket, struct sockaddr *restrict address, socklen_t *restrict address_len);

    @always_inline
    fn read[
        type: DType
    ](inout self, ptr: DTypePointer[type], size: Int64 = -1) raises -> Int64:
        var size_copy = size * sizeof[type]()

        var err = external_call["recv", Int32](
            self._sock_fd,
            ptr,
            size_copy,
            0,
        )

        if err == -1:
            raise "read(): -1 recv error"

        return size_copy

    @always_inline
    fn read_bytes(inout self, size: Int) raises -> DTypePointer[DType.int8]:
        var ptr = DTypePointer[DType.int8].alloc(size)
        var bytes_read = self.read(ptr, size)
        return ptr

    #fn write(inout self):

    fn close(inout self) raises:
        """Closes the socket."""
        if not self._sock_fd:
            return

        var err = external_call["close", Int32](self._sock_fd)

        if err == -1:
            var error_str = String("Socket.close()")
            _ = external_call["perror", UnsafePointer[NoneType]](error_str.unsafe_ptr())
            raise error_str

        self._sock_fd = -1


fn create_socket(family: UInt8 = AF_INET, type: Int32 = SOCK_STREAM, protocol: Int32 = 0) raises -> Socket:
    """Creates a new socket, returning a SocketHandle.

    Args:
      family: The socket family.
      type: The socket type.
      protocol: The socket protocol.

    Returns:
      A Socket.
    """
    return Socket(family, type, protocol)


fn htons(port: UInt16) -> UInt16:
    return external_call["htons", UInt16](port)


# int gethostname(char *name, size_t namelen);
fn gethostname() raises -> String:
    var buf = List[Int8]()
    for _ in range(HOST_NAME_MAX):
        buf.append(0)
    var hostname = String(buf)

    var err = external_call["gethostname", Int32](
        hostname._as_ptr(),
        HOST_NAME_MAX,
    )

    if err == -1:
        var error_str = String("gethostname()")
        _ = external_call["perror", UnsafePointer[NoneType]](error_str.unsafe_ptr())
        raise error_str

    return hostname

# int inet_pton(int af, const char * restrict src, void * restrict dst);
fn inet_pton(family: UInt8, ip_addr: String) raises -> UInt32:
    var num: UInt32 = 0

    var err = external_call["inet_pton", Int32](
        family,
        ip_addr.unsafe_ptr(),
        UnsafePointer.address_of(num),
    )

    if err < 1:
        var error_str = String("inet_pton()")
        _ = external_call["perror", UnsafePointer[NoneType]](error_str.unsafe_ptr())
        raise error_str

    return num


# const char * inet_ntop(int af, const void * restrict src, char * restrict dst, socklen_t size);
fn inet_ntop(family: UInt8, addr: _in_addr) raises -> String:
    var ptr = DTypePointer[DType.int8].alloc(INET_ADDRSTRLEN)

    # It returns NULL if a system error occurs
    var err = external_call["inet_ntop", Int32](
        family,
        UnsafePointer.address_of(addr),
        ptr,
        INET_ADDRSTRLEN,
    )

    if not err:
        var error_str = String("inet_ntop()")
        _ = external_call["perror", UnsafePointer[NoneType]](error_str.unsafe_ptr())
        raise error_str

    return String(ptr, INET_ADDRSTRLEN)


fn main() raises:
    print(gethostname())

    var packed_ip = inet_pton(AF_INET, "127.0.0.1")
    var in_addr = _in_addr()
    in_addr.s_addr = packed_ip
    var address = inet_ntop(AF_INET, in_addr)
    print("address = ", address)

    # Create IPv4 TCP socket
    var tcp_socket = create_socket(AF_INET, SOCK_STREAM, 0)
    tcp_socket.connect("127.0.0.1", 22)

    print("socket fileno = ", tcp_socket.fileno())

    var peer = tcp_socket.getpeername()

    print("getpeername = ", peer[0])
    print("getpeername = ", peer[1])

    var ptr = DTypePointer[DType.uint8].alloc(12)
    var bytes_read = tcp_socket.read(ptr, 12)
    print("bytes read", bytes_read)

    var bytes = tcp_socket.read_bytes(12)
    var ascii_str = String(bytes, 12)
    print("ascii_str = ", ascii_str)

    tcp_socket.close()

    # Create IPv4 UDP socket
    var udp_socket = create_socket(AF_INET, SOCK_DGRAM, 0)
    udp_socket.close()

    # Create IPv6 TCP socket
    var tcpv6_socket = create_socket(AF_INET6, SOCK_STREAM, 0)
    tcpv6_socket.close()

    # Create IPv6 UDP socket
    var udpv6_socket = create_socket(AF_INET6, SOCK_DGRAM, 0)
    udpv6_socket.close()
