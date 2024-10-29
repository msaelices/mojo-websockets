from sys.info import sizeof
from sys import external_call, os_is_macos
from memory import UnsafePointer, Pointer
from utils import StaticTuple, StringRef

from libc import (
    AF_INET,
    AI_PASSIVE,
    SHUT_RDWR,
    SOCK_STREAM,
    SOL_SOCKET,
    SO_ERROR,
    SO_REUSEADDR,
    accept,
    addrinfo,
    c_char,
    c_int,
    c_uint,
    c_void,
    close,
    fcntl,
    getaddrinfo,
    getpeername,
    getsockname,
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

from .aliases import Bytes, Duration
from .utils.string import to_string

alias default_buffer_size = 4096
alias default_tcp_keep_alive = Duration(15 * 1000 * 1000 * 1000)  # 15 seconds


trait AddrInfo:
    fn get_ip_address(self, host: String) raises -> in_addr:
        """
        TODO: Once default functions can be implemented in traits, this function should use the functions currently
        implemented in the `addrinfo_macos` and `addrinfo_unix` structs.
        """
        ...


trait Net:
    fn __init__(inout self) raises:
        ...

    fn __init__(inout self, keep_alive: Duration) raises:
        ...

    # A listen method should be implemented on structs that implement Net.
    # Signature is not enforced for now.
    # fn listen(inout self, network: String, addr: String) raises -> Listener:
    #    ...


trait ListenConfig:
    fn __init__(inout self, keep_alive: Duration) raises:
        ...

    # A listen method should be implemented on structs that implement ListenConfig.
    # Signature is not enforced for now.
    # fn listen(inout self, network: String, address: String) raises -> Listener:
    #    ...


trait Listener(Movable):
    fn __init__(inout self) raises:
        ...

    fn __init__(inout self, addr: TCPAddr) raises:
        ...

    fn accept(borrowed self) raises -> TCPConnection:
        ...

    fn close(self) raises:
        ...

    fn addr(self) -> TCPAddr:
        ...


trait Connection(CollectionElement):
    fn __init__(inout self, laddr: String, raddr: String) raises:
        ...

    fn __init__(inout self, laddr: TCPAddr, raddr: TCPAddr) raises:
        ...

    fn read(self, inout buf: Bytes) raises -> Int:
        ...

    fn write(self, buf: Bytes) raises -> Int:
        ...

    fn close(self) raises:
        ...

    fn local_addr(inout self) raises -> TCPAddr:
        ...

    fn remote_addr(self) raises -> TCPAddr:
        ...


trait Addr(StringableCollectionElement):
    fn __init__(inout self):
        ...

    fn __init__(inout self, ip: String, port: Int):
        ...

    fn network(self) -> String:
        ...



@value
struct NetworkType:
    var value: String

    alias empty = NetworkType("")
    alias tcp = NetworkType("tcp")
    alias tcp4 = NetworkType("tcp4")
    alias tcp6 = NetworkType("tcp6")
    alias udp = NetworkType("udp")
    alias udp4 = NetworkType("udp4")
    alias udp6 = NetworkType("udp6")
    alias ip = NetworkType("ip")
    alias ip4 = NetworkType("ip4")
    alias ip6 = NetworkType("ip6")
    alias unix = NetworkType("unix")


@value
struct TCPAddr(Addr):
    var ip: String
    var port: Int
    var zone: String  # IPv6 addressing zone

    fn __init__(inout self):
        self.ip = String("127.0.0.1")
        self.port = 8000
        self.zone = ""

    fn __init__(inout self, ip: String, port: Int):
        self.ip = ip
        self.port = port
        self.zone = ""

    fn network(self) -> String:
        return NetworkType.tcp.value

    fn __str__(self) -> String:
        if self.zone != "":
            return join_host_port(
                self.ip + "%" + self.zone, self.port.__str__()
            )
        return join_host_port(self.ip, self.port.__str__())


@value
struct TCPConnection(Connection):
    var fd: c_int
    var raddr: TCPAddr
    var laddr: TCPAddr
    var _write_buffer: Bytes

    fn __init__(inout self, laddr: String, raddr: String) raises:
        self.raddr = resolve_internet_addr(NetworkType.tcp4.value, raddr)
        self.laddr = resolve_internet_addr(NetworkType.tcp4.value, laddr)
        self.fd = socket(AF_INET, SOCK_STREAM, 0)
        self._write_buffer = Bytes()

    fn __init__(inout self, laddr: TCPAddr, raddr: TCPAddr) raises:
        self.raddr = raddr
        self.laddr = laddr
        self.fd = socket(AF_INET, SOCK_STREAM, 0)
        self._write_buffer = Bytes()

    fn __init__(inout self, fd: c_int, laddr: TCPAddr, raddr: TCPAddr) raises:
        self.raddr = raddr
        self.laddr = laddr
        self.fd = fd
        self._write_buffer = Bytes()
    
    fn write_buffer(self) -> Bytes:
        return self._write_buffer
    
    fn set_write_buffer(inout self, buf: Bytes):
        self._write_buffer = buf

    fn read(self, inout buf: Bytes) raises -> Int:
        var bytes_recv = recv(
            self.fd,
            buf.unsafe_ptr().offset(buf.size),
            buf.capacity - buf.size,
            0,
        )
        if bytes_recv == -1:
            return 0
        buf.size += bytes_recv
        if bytes_recv == 0:
            return 0
        if bytes_recv < buf.capacity:
            return bytes_recv
        return bytes_recv

    fn write(self, owned msg: String) raises -> Int:
        var bytes_sent = send(self.fd, msg.unsafe_ptr(), len(msg), 0)
        if bytes_sent == -1:
            print("Failed to send response")
        return bytes_sent

    fn write(self, buf: Bytes) raises -> Int:
        var content = to_string(buf)
        var bytes_sent = send(self.fd, content.unsafe_ptr(), len(content), 0)
        if bytes_sent == -1:
            print("Failed to send response")
        _ = content
        return bytes_sent

    fn close(self) raises:
        _ = shutdown(self.fd, SHUT_RDWR)
        var close_status = close(self.fd)
        if close_status == -1:
            print("Failed to close new_sockfd")
    
    fn is_closed(self) -> Bool:
        var error = 0
        var len = socklen_t(sizeof[Int]())
        var result = external_call[
        "getsockopt",
        c_int,
    ](self.fd, SOL_SOCKET, SO_ERROR, UnsafePointer.address_of(error), UnsafePointer.address_of(len))
        return result == -1 or error != 0
    
    fn set_non_blocking(self, non_blocking: Bool) raises:
        var flags = fcntl(self.fd, 3)
        if flags == -1:
            print("Failed to get flags")
            return
        if non_blocking:
            flags |= 2048
        else:
            flags &= ~2048
        var result = fcntl(self.fd, 4, flags)
        if result == -1:
            print("Failed to set flags")

    fn local_addr(inout self) raises -> TCPAddr:
        return self.laddr

    fn remote_addr(self) raises -> TCPAddr:
        return self.raddr


fn resolve_internet_addr(network: String, address: String) raises -> TCPAddr:
    var host: String = ""
    var port: String = ""
    var portnum: Int = 0
    if (
        network == NetworkType.tcp.value
        or network == NetworkType.tcp4.value
        or network == NetworkType.tcp6.value
        or network == NetworkType.udp.value
        or network == NetworkType.udp4.value
        or network == NetworkType.udp6.value
    ):
        if address != "":
            var host_port = split_host_port(address)
            host = host_port.host
            port = host_port.port
            portnum = atol(port.__str__())
    elif (
        network == NetworkType.ip.value
        or network == NetworkType.ip4.value
        or network == NetworkType.ip6.value
    ):
        if address != "":
            host = address
    elif network == NetworkType.unix.value:
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

    fn __init__(inout self, host: String, port: String):
        self.host = host
        self.port = port


fn split_host_port(hostport: String) raises -> HostPort:
    var host: String = ""
    var port: String = ""
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


fn convert_binary_port_to_int(port: UInt16) -> Int:
    return int(ntohs(port))


fn convert_binary_ip_to_string(
    owned ip_address: UInt32, address_family: Int32, address_length: UInt32
) -> String:
    """Convert a binary IP address to a string by calling inet_ntop.

    Args:
        ip_address: The binary IP address.
        address_family: The address family of the IP address.
        address_length: The length of the address.

    Returns:
        The IP address as a string.
    """
    # It seems like the len of the buffer depends on the length of the string IP.
    # Allocating 10 works for localhost (127.0.0.1) which I suspect is 9 bytes + 1 null terminator byte. So max should be 16 (15 + 1).
    var ip_buffer = UnsafePointer[c_char].alloc(16)
    var ip_address_ptr = UnsafePointer.address_of(ip_address).bitcast[Byte]()
    _ = inet_ntop(address_family, ip_address_ptr, ip_buffer, 16)

    var string_buf = ip_buffer.bitcast[Int8]()
    var index = 0
    while True:
        if string_buf[index] == 0:
            break
        index += 1

    return StringRef(string_buf, index)


fn get_sock_name(fd: Int32) raises -> HostPort:
    """Return the address of the socket."""
    var local_address_ptr = UnsafePointer[sockaddr].alloc(1)
    var local_address_ptr_size = socklen_t(sizeof[sockaddr]())
    var status = getsockname(
        fd,
        local_address_ptr,
        UnsafePointer[socklen_t].address_of(local_address_ptr_size),
    )
    if status == -1:
        raise Error("get_sock_name: Failed to get address of local socket.")
    var addr_in = local_address_ptr.bitcast[sockaddr_in]()[]

    return HostPort(
        host=convert_binary_ip_to_string(addr_in.sin_addr.s_addr, AF_INET, 16),
        port=convert_binary_port_to_int(addr_in.sin_port).__str__(),
    )


fn get_peer_name(fd: Int32) raises -> HostPort:
    """Return the address of the peer connected to the socket."""
    var remote_address_ptr = UnsafePointer[sockaddr].alloc(1)
    var remote_address_ptr_size = socklen_t(sizeof[sockaddr]())

    var status = getpeername(
        fd,
        remote_address_ptr,
        UnsafePointer[socklen_t].address_of(remote_address_ptr_size),
    )
    if status == -1:
        raise Error("get_peer_name: Failed to get address of remote socket.")

    # Cast sockaddr struct to sockaddr_in to convert binary IP to string.
    var addr_in = remote_address_ptr.bitcast[sockaddr_in]()[]

    return HostPort(
        host=convert_binary_ip_to_string(addr_in.sin_addr.s_addr, AF_INET, 16),
        port=convert_binary_port_to_int(addr_in.sin_port).__str__(),
    )


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

    fn __init__(inout self):
        self.ai_flags = 0
        self.ai_family = 0
        self.ai_socktype = 0
        self.ai_protocol = 0
        self.ai_addrlen = 0
        self.ai_canonname = UnsafePointer[c_char]()
        self.ai_addr = UnsafePointer[sockaddr]()
        self.ai_next = UnsafePointer[c_void]()

    fn get_ip_address(self, host: String) raises -> in_addr:
        """
        Returns an IP address based on the host.
        This is a MacOS-specific implementation.

        Args:
            host: String - The host to get the IP from.

        Returns:
            in_addr - The IP address.
        """
        var host_ptr = host.unsafe_cstr_ptr()
        var servinfo = Pointer.address_of(Self())
        var servname = UnsafePointer[Int8]()

        var hints = Self()
        hints.ai_family = AF_INET
        hints.ai_socktype = SOCK_STREAM
        hints.ai_flags = AI_PASSIVE

        var error = external_call[
            "getaddrinfo",
            Int32,
        ](host_ptr, servname, Pointer.address_of(hints), Pointer.address_of(servinfo))

        if error != 0:
            print("getaddrinfo failed with error code: " + error.__str__())
            raise Error("Failed to get IP address. getaddrinfo failed.")

        var addrinfo = servinfo[]

        var ai_addr = addrinfo.ai_addr
        if not ai_addr:
            print("ai_addr is null")
            raise Error(
                "Failed to get IP address. getaddrinfo was called successfully,"
                " but ai_addr is null."
            )

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
    var ai_next: UnsafePointer[c_void]

    fn __init__(inout self):
        self.ai_flags = 0
        self.ai_family = 0
        self.ai_socktype = 0
        self.ai_protocol = 0
        self.ai_addrlen = 0
        self.ai_addr = UnsafePointer[sockaddr]()
        self.ai_canonname = UnsafePointer[c_char]()
        self.ai_next = UnsafePointer[c_void]()

    fn get_ip_address(self, host: String) raises -> in_addr:
        """
        Returns an IP address based on the host.
        This is a Unix-specific implementation.

        Args:
            host: String - The host to get IP from.

        Returns:
            UInt32 - The IP address.
        """
        var host_ptr = host.unsafe_cstr_ptr()
        var self_addrinfo = rebind[addrinfo](Self())
        var servinfo = UnsafePointer[addrinfo]().alloc(1)
        servinfo.init_pointee_move(self_addrinfo)

        var hints = rebind[addrinfo](Self())
        hints.ai_family = AF_INET
        hints.ai_socktype = SOCK_STREAM
        hints.ai_flags = AI_PASSIVE

        var error = getaddrinfo(
            host_ptr,
            UnsafePointer[c_char](),
            UnsafePointer.address_of(hints),
            UnsafePointer.address_of(servinfo),
        )
        if error != 0:
            print("getaddrinfo failed")
            raise Error("Failed to get IP address. getaddrinfo failed.")

        var addrinfo = servinfo[]

        var ai_addr = addrinfo.ai_addr
        if not ai_addr:
            print("ai_addr is null")
            raise Error(
                "Failed to get IP address. getaddrinfo was called successfully,"
                " but ai_addr is null."
            )

        var addr_in = ai_addr.bitcast[sockaddr_in]()[]

        return addr_in.sin_addr


@value
struct TCPListener(Listener):
    """
    A TCP listener that listens for incoming connections and can accept them.
    """

    var fd: c_int
    var _addr: TCPAddr

    fn __init__(inout self) raises:
        self._addr = TCPAddr("localhost", 8080)
        self.fd = socket(AF_INET, SOCK_STREAM, 0)

    fn __init__(inout self, addr: TCPAddr) raises:
        self._addr = addr
        self.fd = socket(AF_INET, SOCK_STREAM, 0)

    fn __init__(inout self, addr: TCPAddr, fd: c_int) raises:
        self._addr = addr
        self.fd = fd

    fn listen(inout self) raises: 
        var address_family = AF_INET
        var ip_buf_size = 4
        var addr = self._addr

        var sockfd = self.fd
        if sockfd == -1:
            print("Socket creation error")

        var yes = 1
        _ = setsockopt(
            sockfd,
            SOL_SOCKET,
            SO_REUSEADDR,
            UnsafePointer[Int].address_of(yes).bitcast[c_void](),
            sizeof[Int](),
        )

        var ip_buf = UnsafePointer[c_void].alloc(ip_buf_size)
        _ = inet_pton(
            address_family, addr.ip.unsafe_cstr_ptr(), ip_buf
        )
        var raw_ip = ip_buf.bitcast[c_uint]()[]
        var bin_port = htons(UInt16(addr.port))

        var ai = sockaddr_in(
            address_family, bin_port, raw_ip, StaticTuple[c_char, 8]()
        )
        var ai_ptr = Pointer.address_of(ai)

        # var bind = bind(sockfd, ai_ptr, sizeof[sockaddr_in]())
        var bind = external_call["bind", c_int](
            sockfd, ai_ptr, sizeof[sockaddr_in]()
        )
        if bind != 0:
            print(
                "Bind attempt failed. The address might be in use or"
                " the socket might not be available."
            )
            _ = shutdown(sockfd, SHUT_RDWR)

        if listen(sockfd, c_int(128)) == -1:
            print("Listen failed.\n on sockfd " + sockfd.__str__())

        print(
            "\nServer is listening on "
            + addr.ip
            + ":"
            + addr.port.__str__()
        )
        print("Ready to accept connections...")

    fn accept(self) raises -> TCPConnection:
        var their_addr = sockaddr(0, StaticTuple[c_char, 14]())
        var their_addr_ptr = UnsafePointer.address_of(their_addr)
        var sin_size = socklen_t(sizeof[socklen_t]())

        var new_sockfd = accept(
            self.fd, their_addr_ptr, UnsafePointer[socklen_t].address_of(sin_size)
        )
        if new_sockfd == -1:
            print(
                "Failed to accept connection, system accept() returned an"
                " error."
            )
        var peer = get_peer_name(new_sockfd)
        print("Got connection from " + peer.host + ":" + peer.port)

        return TCPConnection(
            new_sockfd, self._addr, TCPAddr(peer.host, atol(peer.port)), 
        )

    fn close(self) raises:
        _ = shutdown(self.fd, SHUT_RDWR)
        var close_status = close(self.fd)
        if close_status == -1:
            print("Failed to close new_sockfd")

    fn addr(self) -> TCPAddr:
        return self._addr


fn create_connection(
    host: String, port: UInt16
) raises -> TCPConnection:
    """
    Connect to a server using a socket.

    Args:
        host: String - The host to connect to.
        port: UInt16 - The port to connect to.

    Returns:
        Int32 - The socket file descriptor.
    """
    var ip: in_addr
    print("Connecting to " + host + " on port " + port.__str__())
    if os_is_macos():
        ip = addrinfo_macos().get_ip_address(host)
    else:
        ip = addrinfo_unix().get_ip_address(host)


    # Convert ip address to network byte order.
    var addr: sockaddr_in = sockaddr_in(
        AF_INET, htons(port), ip, StaticTuple[c_char, 8](0, 0, 0, 0, 0, 0, 0, 0)
    )
    var addr_ptr = Pointer[sockaddr_in].address_of(addr)
    var sock = socket(AF_INET, SOCK_STREAM, 0)

    if (
        external_call["connect", c_int](sock, addr_ptr, sizeof[sockaddr_in]())
        == -1
    ):
        _ = shutdown(sock, SHUT_RDWR)
        raise Error("Failed to connect to server")

    var laddr = TCPAddr()
    var raddr = TCPAddr(host, int(port))
    var conn = TCPConnection(sock, laddr, raddr)

    return conn


fn create_listener(host: String, port: UInt16) raises -> TCPListener:
    """
    Create a listener that listens for incoming connections.

    Args:
        host: String - The host to listen on.
        port: UInt16 - The port to listen on.

    Returns:
        TCPListener - The listener.
    """
    var addr = TCPAddr(host, int(port))
    return TCPListener(addr)
