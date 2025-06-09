from collections import Optional
from sys.info import alignof, sizeof
from sys import external_call, os_is_macos
from sys.ffi import OpaquePointer
from memory import UnsafePointer, Pointer, Span
from time import sleep
from utils import StaticTuple, Variant

from websockets.aliases import Bytes, Duration

from websockets.libc import (
    AF_INET,
    AF_INET6,
    AI_PASSIVE,
    INET_ADDRSTRLEN,
    INET6_ADDRSTRLEN,
    SHUT_RDWR,
    SOCK_STREAM,
    SOL_SOCKET,
    SO_ERROR,
    SO_REUSEADDR,
    accept,
    addrinfo,
    c_char,
    c_uchar,
    c_int,
    c_uint,
    c_void,
    close,
    gai_strerror,
    getpeername,
    getsockname,
    getsockopt,
    htons,
    in_addr,
    inet_ntop,
    inet_pton,
    listen,
    ntohs,
    recv,
    send,
    setsockopt,
    shutdown,
    sockaddr,
    sockaddr_in,
    socket,
    socklen_t,
)
from websockets.logger import logger
from websockets.socket import Socket
from websockets.utils.string import to_string

alias default_buffer_size = 4096
alias default_tcp_keep_alive = Duration(15 * 1000 * 1000 * 1000)  # 15 seconds

alias MissingPortError = Error("missing port in address")
alias TooManyColonsError = Error("too many colons in address")


trait AddrInfo:
    fn get_ip_address(self, host: String) raises -> in_addr:
        """
        TODO: Once default functions can be implemented in traits, this function should use the functions currently
        implemented in the `addrinfo_macos` and `addrinfo_unix` structs.
        """
        ...


trait Net:
    fn __init__(out self) raises:
        ...

    fn __init__(out self, keep_alive: Duration) raises:
        ...

    # A listen method should be implemented on structs that implement Net.
    # Signature is not enforced for now.
    # fn listen(mut self, network: String, addr: String) raises -> Listener:
    #    ...


trait Connection:
    fn __init__(out self, laddr: String, raddr: String) raises:
        ...

    fn __init__(out self, laddr: TCPAddr, raddr: TCPAddr) raises:
        ...

    fn read(self, mut buf: Bytes) raises -> Int:
        ...

    fn write(self, buf: Bytes) raises -> Int:
        ...

    fn close(self) raises:
        ...

    fn local_addr(mut self) raises -> TCPAddr:
        ...

    fn remote_addr(self) raises -> TCPAddr:
        ...


trait Addr(Stringable, Copyable, Representable, Writable):
    fn __init__(out self):
        ...

    fn __init__(out self, ip: String, port: UInt16):
        ...

    fn network(self) -> String:
        ...


@value
struct NetworkType:
    var value: String

    alias EMPTY = NetworkType("")
    alias TCP = NetworkType("tcp")
    alias TCP4 = NetworkType("tcp4")
    alias TCP6 = NetworkType("tcp6")
    alias UDP = NetworkType("udp")
    alias UDP4 = NetworkType("udp4")
    alias UDP6 = NetworkType("udp6")
    alias IP = NetworkType("ip")
    alias IP4 = NetworkType("ip4")
    alias IP6 = NetworkType("ip6")
    alias UNIX = NetworkType("unix")


@value
struct TCPAddr(Addr):
    var ip: String
    var port: UInt16
    var zone: String  # IPv6 addressing zone

    fn __init__(out self):
        self.ip = "127.0.0.1"
        self.port = 8000
        self.zone = ""

    fn __init__(out self, ip: String, port: UInt16):
        self.ip = ip
        self.port = port
        self.zone = ""

    fn __copyinit__(out self, other: Self):
        self.ip = other.ip
        self.port = other.port
        self.zone = other.zone

    fn network(self) -> String:
        return NetworkType.TCP.value

    fn __eq__(self, other: Self) -> Bool:
        return (
            self.ip == other.ip and self.port == other.port and self.zone == other.zone
        )

    fn __ne__(self, other: Self) -> Bool:
        return not self == other

    fn __str__(self) -> String:
        if self.zone != "":
            return join_host_port(self.ip + "%" + self.zone, String(self.port))
        return join_host_port(self.ip, String(self.port))

    fn __repr__(self) -> String:
        return String.write(self)

    fn write_to[W: Writer, //](self, mut writer: W):
        writer.write(
            "TCPAddr(",
            "ip=",
            repr(self.ip),
            ", port=",
            String(self.port),
            ", zone=",
            repr(self.zone),
            ")",
        )


struct TCPConnection:
    var socket: Socket[TCPAddr]

    fn __init__(out self, owned socket: Socket[TCPAddr]):
        self.socket = socket^

    fn __moveinit__(out self, owned existing: Self):
        self.socket = existing.socket^

    fn __copyinit__(out self, existing: Self):
        self.socket = existing.socket

    fn connect(mut self, host: String, port: Int) raises:
        self.socket.connect(host, port)

    fn read(self, mut buf: Bytes) raises -> Int:
        try:
            return self.socket.receive(buf)
        except e:
            if String(e) == "EOF":
                raise e
            else:
                logger.error(e)
                raise Error("TCPConnection.read: Failed to read data from connection.")

    fn write(self, buf: Span[Byte]) raises -> Int:
        if buf[-1] == 0:
            raise Error("TCPConnection.write: Buffer must not be null-terminated.")

        try:
            return self.socket.send(buf)
        except e:
            logger.error("TCPConnection.write: Failed to write data to connection.")
            raise e

    fn close(mut self) raises:
        self.socket.close()

    fn shutdown(mut self) raises:
        self.socket.shutdown()

    fn teardown(mut self) raises:
        self.socket.teardown()

    fn is_closed(self) -> Bool:
        return self.socket._closed

    # TODO: Switch to property or return ref when trait supports attributes.
    fn local_addr(self) -> TCPAddr:
        return self.socket.local_address()

    fn remote_addr(self) -> Optional[TCPAddr]:
        return self.socket.remote_address()


fn resolve_internet_addr(network: String, address: String) raises -> TCPAddr:
    var host: String = ""
    var port: String
    var portnum: Int = 0
    if (
        network == NetworkType.TCP.value
        or network == NetworkType.TCP4.value
        or network == NetworkType.TCP6.value
        or network == NetworkType.UDP.value
        or network == NetworkType.UDP4.value
        or network == NetworkType.UDP6.value
    ):
        if address != "":
            var host_port = split_host_port(address)
            host = host_port.host
            port = host_port.port
            portnum = atol(port.__str__())
    elif (
        network == NetworkType.IP.value
        or network == NetworkType.IP4.value
        or network == NetworkType.IP6.value
    ):
        if address != "":
            host = address
    elif network == NetworkType.UNIX.value:
        raise Error("Unix addresses not supported yet")
    else:
        raise Error("unsupported network type: " + network)
    return TCPAddr(host, portnum)


fn join_host_port(host: String, port: String) -> String:
    if host.find(":") != -1:  # must be IPv6 literal
        return "[" + host + "]:" + port
    return host + ":" + port


alias missingPortError = Error("missing port in address")
alias tooManyColonsError = Error("too many colons in address")


struct HostPort:
    var host: String
    var port: String

    fn __init__(out self, host: String, port: String):
        self.host = host
        self.port = port


fn split_host_port(hostport: String) raises -> HostPort:
    var host: String
    var port: String
    var colon_index = hostport.rfind(":")
    var j: Int = 0
    var k: Int = 0

    if colon_index == -1:
        raise missingPortError
    if hostport[0] == "[":
        var end_bracket_index = hostport.find("]")
        if end_bracket_index == -1:
            raise Error("missing ']' in address")
        if end_bracket_index + 1 == len(hostport):
            raise missingPortError
        elif end_bracket_index + 1 == colon_index:
            host = hostport[1:end_bracket_index]
            j = 1
            k = end_bracket_index + 1
        else:
            if hostport[end_bracket_index + 1] == ":":
                raise tooManyColonsError
            else:
                raise missingPortError
    else:
        host = hostport[:colon_index]
        if host.find(":") != -1:
            raise tooManyColonsError
    if hostport[j:].find("[") != -1:
        raise Error("unexpected '[' in address")
    if hostport[k:].find("]") != -1:
        raise Error("unexpected ']' in address")
    port = hostport[colon_index + 1 :]

    if port == "":
        raise missingPortError
    if host == "":
        raise Error("missing host")
    return HostPort(host, port)


fn parse_address(address: String) raises -> (String, UInt16):
    """Parse an address string into a host and port.

    Args:
        address: The address string.

    Returns:
        A tuple containing the host and port.
    """
    var colon_index = address.rfind(":")
    if colon_index == -1:
        raise MissingPortError

    var host: String
    var port: String
    var j: Int = 0
    var k: Int = 0

    if address[0] == "[":
        var end_bracket_index = address.find("]")
        if end_bracket_index == -1:
            raise Error("missing ']' in address")

        if end_bracket_index + 1 == len(address):
            raise MissingPortError
        elif end_bracket_index + 1 == colon_index:
            host = address[1:end_bracket_index]
            j = 1
            k = end_bracket_index + 1
        else:
            if address[end_bracket_index + 1] == ":":
                raise TooManyColonsError
            else:
                raise MissingPortError
    else:
        host = address[:colon_index]
        if host.find(":") != -1:
            raise TooManyColonsError

    if address[j:].find("[") != -1:
        raise Error("unexpected '[' in address")
    if address[k:].find("]") != -1:
        raise Error("unexpected ']' in address")

    port = address[colon_index + 1 :]
    if port == "":
        raise MissingPortError
    if host == "":
        raise Error("missing host")
    return host, UInt16(Int(port))


fn binary_port_to_int(port: UInt16) -> Int:
    """Convert a binary port to an integer.

    Args:
        port: The binary port.

    Returns:
        The port as an integer.
    """
    return Int(ntohs(port))


fn binary_ip_to_string[
    address_family: Int32
](owned ip_address: UInt32) raises -> String:
    """Convert a binary IP address to a string by calling `inet_ntop`.

    Parameters:
        address_family: The address family of the IP address.

    Args:
        ip_address: The binary IP address.

    Returns:
        The IP address as a string.
    """
    constrained[
        Int(address_family) in [AF_INET, AF_INET6],
        "Address family must be either AF_INET or AF_INET6.",
    ]()
    var ip: String

    @parameter
    if address_family == AF_INET:
        ip = inet_ntop[address_family, INET_ADDRSTRLEN](ip_address)
    else:
        ip = inet_ntop[address_family, INET6_ADDRSTRLEN](ip_address)

    return ip


@value
@register_passable("trivial")
struct addrinfo_macos(AddrInfo):
    """
    For MacOS, I had to swap the order of ai_canonname and ai_addr.
    https://stackoverflow.com/questions/53575101/calling-getaddrinfo-directly-from-python-ai-addr-is-null-pointer.
    """

    var ai_flags: c_int
    var ai_family: c_int
    var ai_socktype: c_int
    var ai_protocol: c_int
    var ai_addrlen: socklen_t
    var ai_canonname: UnsafePointer[c_char]
    var ai_addr: UnsafePointer[sockaddr]
    var ai_next: UnsafePointer[c_void]

    fn __init__(out self):
        self.ai_flags = 0
        self.ai_family = 0
        self.ai_socktype = 0
        self.ai_protocol = 0
        self.ai_addrlen = 0
        self.ai_canonname = UnsafePointer[c_char]()
        self.ai_addr = UnsafePointer[sockaddr]()
        self.ai_next = UnsafePointer[c_void]()

    fn get_from_host(self, owned host: String) raises -> UnsafePointer[Self]:
        """
        Returns an IP address based on the host.
        This is a MacOS-specific implementation.

        Args:
            host: String - The host to get the IP from.

        Returns:
            The IP address.
        """
        var host_ptr = host.unsafe_cstr_ptr().origin_cast[mut=False]()
        var servinfo = UnsafePointer(to=self)
        var servname = UnsafePointer[Int8]()

        var hints = Self()
        hints.ai_family = AF_INET
        hints.ai_socktype = SOCK_STREAM
        hints.ai_flags = AI_PASSIVE

        var error = external_call[
            "getaddrinfo",
            Int32,
        ](host_ptr, servname, UnsafePointer(to=hints), UnsafePointer(to=servinfo))

        if error != 0:
            print("getaddrinfo failed with error code: " + error.__str__())
            raise Error("Failed to get IP address. getaddrinfo failed.")

        var ai_addr = servinfo[].ai_addr
        if not ai_addr:
            print("ai_addr is null")
            raise Error(
                "Failed to get IP address. getaddrinfo was called successfully,"
                " but ai_addr is null."
            )
        return servinfo

    fn get_ip_address(self, host: String) raises -> in_addr:
        """
        Returns an IP address based on the host.
        This is a MacOS-specific implementation.

        Args:
            host: String - The host to get the IP from.

        Returns:
            The IP address.
        """
        var addrinfo_ptr = self.get_from_host(host)

        var ai_addr = addrinfo_ptr[].ai_addr
        var addr_in = ai_addr.bitcast[sockaddr_in]()[]

        return addr_in.sin_addr


@value
@register_passable("trivial")
struct addrinfo_unix(AddrInfo):
    """
    Standard addrinfo struct for Unix systems. Overwrites the existing libc `getaddrinfo` function to adhere to the AnAddrInfo trait.
    """

    var ai_flags: c_int
    var ai_family: c_int
    var ai_socktype: c_int
    var ai_protocol: c_int
    var ai_addrlen: socklen_t
    var ai_addr: UnsafePointer[sockaddr]
    var ai_canonname: UnsafePointer[c_char]
    var ai_next: OpaquePointer

    fn __init__(
        out self,
        ai_flags: c_int = 0,
        ai_family: c_int = 0,
        ai_socktype: c_int = 0,
        ai_protocol: c_int = 0,
        ai_addrlen: socklen_t = 0,
    ):
        self.ai_flags = ai_flags
        self.ai_family = ai_family
        self.ai_socktype = ai_socktype
        self.ai_protocol = ai_protocol
        self.ai_addrlen = ai_addrlen
        self.ai_canonname = UnsafePointer[c_char]()
        self.ai_addr = UnsafePointer[sockaddr]()
        self.ai_next = OpaquePointer()

    fn get_from_host(self, owned host: String) raises -> UnsafePointer[Self]:
        """
        Returns an IP address based on the host.
        This is a MacOS-specific implementation.

        Args:
            host: String - The host to get the IP from.

        Returns:
            The IP address.
        """
        var result = UnsafePointer[Self]()
        var hints = Self(
            ai_flags=0, ai_family=AF_INET, ai_socktype=SOCK_STREAM, ai_protocol=0
        )
        try:
            getaddrinfo(host, String(), hints, result)
        except e:
            logger.error("Failed to get IP address.")
            raise e

        if not result[].ai_addr:
            freeaddrinfo(result)
            raise Error(
                "Failed to get IP address because the response's `ai_addr` was null."
            )

        return result

    fn get_ip_address(self, host: String) raises -> in_addr:
        """Returns an IP address based on the host.
        This is a MacOS-specific implementation.

        Args:
            host: String - The host to get the IP from.

        Returns:
            The IP address.
        """
        result_ptr = self.get_from_host(host)

        var ip = result_ptr[].ai_addr.bitcast[sockaddr_in]()[].sin_addr
        freeaddrinfo(result_ptr)
        return ip


struct TCPListener:
    """
    A TCP listener that listens for incoming connections and can accept them.
    """

    var socket: Socket[TCPAddr]

    fn __init__(out self, owned socket: Socket[TCPAddr]):
        self.socket = socket^

    fn __init__(out self) raises:
        self.socket = Socket[TCPAddr]()

    fn __moveinit__(out self, owned existing: Self):
        self.socket = existing.socket^

    fn __copyinit__(out self, existing: Self):
        self.socket = existing.socket

    fn accept(self) raises -> TCPConnection:
        return TCPConnection(self.socket.accept())

    fn close(mut self) raises -> None:
        return self.socket.close()

    fn shutdown(mut self) raises -> None:
        return self.socket.shutdown()

    fn teardown(mut self) raises:
        self.socket.teardown()

    fn addr(self) -> TCPAddr:
        return self.socket.local_address()


struct ListenConfig:
    var _keep_alive: Duration

    fn __init__(out self, keep_alive: Duration = default_tcp_keep_alive):
        self._keep_alive = keep_alive

    fn listen[
        address_family: Int = AF_INET
    ](mut self, host: String, port: Int) raises -> TCPListener:
        constrained[
            address_family in [AF_INET, AF_INET6],
            "Address family must be either AF_INET or AF_INET6.",
        ]()
        var addr = TCPAddr(host, port)
        var socket: Socket[TCPAddr]
        try:
            socket = Socket[TCPAddr]()
        except e:
            logger.error(e)
            raise Error(
                "ListenConfig.listen: Failed to create listener due to socket creation"
                " failure."
            )

        try:

            @parameter
            # TODO: do we want to reuse port on linux? currently doesn't work
            if os_is_macos():
                socket.set_socket_option(SO_REUSEADDR, 1)
        except e:
            logger.warn("ListenConfig.listen: Failed to set socket as reusable", e)

        var bind_success = False
        var bind_fail_logged = False
        while not bind_success:
            try:
                socket.bind(addr.ip, addr.port)
                bind_success = True
            except e:
                if not bind_fail_logged:
                    print("Bind attempt failed: ", e)
                    print("Retrying. Might take 10-15 seconds.")
                    bind_fail_logged = True
                print(".", end="", flush=True)

                try:
                    socket.shutdown()
                except e:
                    logger.error("ListenConfig.listen: Failed to shutdown socket:", e)
                    # TODO: Should shutdown failure be a hard failure? We can still ungracefully close the socket.
                sleep(UInt(1))

        try:
            socket.listen(128)
        except e:
            logger.error(e)
            raise Error(
                "ListenConfig.listen: Listen failed on sockfd: " + String(socket.fd)
            )

        var listener = TCPListener(socket^)
        var msg = String.write(
            "\n🔥 Listening on ", "ws://", addr.ip, ":", String(addr.port)
        )
        print(msg)
        print("Ready to accept connections...")

        return listener^


fn get_address_info(host: String) raises -> Variant[addrinfo_macos, addrinfo_unix]:
    """
    Get the IP address of a host.

    Args:
        host: String - The host to get the IP address of.

    Returns:
        The IP address.
    """
    if os_is_macos():
        return addrinfo_macos().get_from_host(host)[]
    return addrinfo_unix().get_from_host(host)[]


fn _getaddrinfo[
    T: AddrInfo, hints_origin: ImmutableOrigin, result_origin: MutableOrigin, //
](
    nodename: UnsafePointer[c_char, mut=False],
    servname: UnsafePointer[c_char, mut=False],
    hints: Pointer[T, hints_origin],
    res: Pointer[UnsafePointer[T], result_origin],
) -> c_int:
    """Libc POSIX `getaddrinfo` function.

    Args:
        nodename: The node name.
        servname: The service name.
        hints: A Pointer to the hints.
        res: A UnsafePointer to the result.

    Returns:
        0 on success, an error code on failure.

    #### C Function
    ```c
    int getaddrinfo(const char *restrict nodename, const char *restrict servname, const struct addrinfo *restrict hints, struct addrinfo **restrict res)
    ```

    #### Notes:
    * Reference: https://man7.org/linux/man-pages/man3/getaddrinfo.3p.html
    """
    return external_call[
        "getaddrinfo",
        c_int,  # FnName, RetType
        UnsafePointer[c_char, mut=False],
        UnsafePointer[c_char, mut=False],
        Pointer[T, hints_origin],  # Args
        Pointer[UnsafePointer[T], result_origin],  # Args
    ](nodename, servname, hints, res)


fn getaddrinfo[
    T: AddrInfo, //
](
    owned node: String, owned service: String, hints: T, mut res: UnsafePointer[T]
) raises:
    """Libc POSIX `getaddrinfo` function.

    Args:
        node: The node name.
        service: The service name.
        hints: A Pointer to the hints.
        res: A UnsafePointer to the result.

    Raises:
        Error: If an error occurs while attempting to receive data from the socket.
        EAI_AGAIN: The name could not be resolved at this time. Future attempts may succeed.
        EAI_BADFLAGS: The `ai_flags` value was invalid.
        EAI_FAIL: A non-recoverable error occurred when attempting to resolve the name.
        EAI_FAMILY: The `ai_family` member of the `hints` argument is not supported.
        EAI_MEMORY: Out of memory.
        EAI_NONAME: The name does not resolve for the supplied parameters.
        EAI_SERVICE: The `servname` is not supported for `ai_socktype`.
        EAI_SOCKTYPE: The `ai_socktype` is not supported.
        EAI_SYSTEM: A system error occurred. `errno` is set in this case.

    #### C Function
    ```c
    int getaddrinfo(const char *restrict nodename, const char *restrict servname, const struct addrinfo *restrict hints, struct addrinfo **restrict res)
    ```

    #### Notes:
    * Reference: https://man7.org/linux/man-pages/man3/getaddrinfo.3p.html.
    """
    var result = _getaddrinfo(
        node.unsafe_cstr_ptr().origin_cast[mut=False](),
        service.unsafe_cstr_ptr().origin_cast[mut=False](),
        Pointer(to=hints),
        Pointer(to=res),
    )
    if result != 0:
        # gai_strerror returns a char buffer that we don't know the length of.
        var err = gai_strerror(result)
        var msg = String()
        var i = 0
        while err[i] != 0:
            i += 1

        msg.write_bytes(
            Span[Byte, __origin_of(err)](ptr=err.bitcast[c_uchar](), length=i)
        )
        raise Error("getaddrinfo: ", msg)


fn freeaddrinfo[T: AddrInfo, //](ptr: UnsafePointer[T]):
    """Free the memory allocated by `getaddrinfo`."""
    external_call["freeaddrinfo", NoneType, UnsafePointer[T]](ptr)


# fn create_connection(
#     host: String, port: UInt16
# ) raises -> TCPConnection:
#     """
#     Connect to a server using a socket.
#
#     Args:
#         host: String - The host to connect to.
#         port: UInt16 - The port to connect to.
#
#     Returns:
#         Int32 - The socket file descriptor.
#     """
#     var ip: in_addr
#     print("Connecting to " + host + " on port " + port.__str__())
#     if os_is_macos():
#         ip = addrinfo_macos().get_ip_address(host)
#     else:
#         ip = addrinfo_unix().get_ip_address(host)
#
#     # Convert ip address to network byte order.
#     var addr: sockaddr_in = sockaddr_in(
#         AF_INET, htons(port), ip, StaticTuple[c_char, 8](0, 0, 0, 0, 0, 0, 0, 0)
#     )
#     var addr_ptr = Pointer[sockaddr_in](to=addr)
#     var sock = socket(AF_INET, SOCK_STREAM, 0)
#
#     if (
#         external_call["connect", c_int](sock, addr_ptr, sizeof[sockaddr_in]())
#         == -1
#     ):
#         _ = shutdown(sock, SHUT_RDWR)
#         raise Error("Failed to connect to server")
#
#     var laddr = TCPAddr()
#     var raddr = TCPAddr(host, Int(port))
#     var conn = TCPConnection(sock, laddr, raddr)
#
#     return conn


# fn create_listener(host: String, port: UInt16) raises -> TCPListener:
#     """
#     Create a listener that listens for incoming connections.
#
#     Args:
#         host: String - The host to listen on.
#         port: UInt16 - The port to listen on.
#
#     Returns:
#         TCPListener - The listener.
#     """
#     var addr = TCPAddr(host, Int(port))
#     return TCPListener(addr)
