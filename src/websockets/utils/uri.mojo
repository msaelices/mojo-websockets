from utils import Variant
from libc import Bytes 

from .string import (
    bytes,
    bytes_equal,
    HTTP,
    HTTP10,
    HTTP11,
    HTTPS,
    SLASH,
)


@value
struct URI:
    var _original_path: String
    var _hash: String
    var scheme: String
    var path: String
    var query_string: String
    var host: String

    var full_uri: String
    var request_uri: String

    var username: String
    var password: String

    @staticmethod
    fn parse(uri: String) -> Variant[URI, String]:
        var u = URI(uri)
        try:
            u._parse()
        except e:
            return "Failed to parse URI: " + str(e)

        return u
    
    @staticmethod
    fn parse_raises(uri: String) raises -> URI:
        var u = URI(uri)
        u._parse()
        return u

    fn __init__(
        inout self,
        uri: String = "",
    ) -> None:
        self._original_path = "/"
        self._hash = ""
        self.scheme = 
        self.path = "/"
        self.query_string = ""
        self.host = ""
        self.full_uri = uri
        self.request_uri = ""
        self.username = ""
        self.password = ""

    fn is_https(self) -> Bool:
        return self.scheme == https

    fn is_http(self) -> Bool:
        return self.scheme == http or len(self.scheme) == 0

    fn _parse(inout self) raises -> None:
        var raw_uri = self.full_uri
        var proto_str = String(HTTP11)
        var is_https = False

        var proto_end = raw_uri.find("://")
        var remainder_uri: String
        if proto_end >= 0:
            proto_str = raw_uri[:proto_end]
            if proto_str == https:
                is_https = True
            remainder_uri = raw_uri[proto_end + 3:]
        else:
            remainder_uri = raw_uri
        
        self.scheme = proto_str^
        
        var path_start = remainder_uri.find("/")
        var host_and_port: String
        var request_uri: String
        if path_start >= 0:
            host_and_port = remainder_uri[:path_start]
            request_uri = remainder_uri[path_start:]
            self.host = host_and_port[:path_start]
        else:
            host_and_port = remainder_uri
            request_uri = SLASH
            self.host = host_and_port

        if is_https:
            self.scheme = https
        else:
            self.scheme = http
        
        var n = request_uri.find("?")
        if n >= 0:
            self._original_path = request_uri[:n]
            self.query_string = request_uri[n + 1 :]
        else:
            self._original_path = request_uri
            self.query_string = Bytes()

        self.path = self._original_path
        self.request_uri = request_uri

