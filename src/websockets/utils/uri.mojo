from collections import Optional
from utils import StringSlice, Variant

from websockets.aliases import Bytes
from websockets.utils.string import (
    bytes,
    bytes_equal,
    HTTP,
    HTTP10,
    HTTP11,
    HTTPS,
    WSS,
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
    fn parse(uri: String) -> URI:
        var proto_str = String(HTTP11)
        var is_https = False

        var proto_end = uri.find("://")
        var remainder_uri: String
        if proto_end >= 0:
            proto_str = uri[:proto_end]
            if proto_str == HTTPS:
                is_https = True
            remainder_uri = uri[proto_end + 3 :]
        else:
            remainder_uri = uri

        var path_start = remainder_uri.find("/")
        var host_and_port: String
        var request_uri: String
        var host: String
        if path_start >= 0:
            host_and_port = remainder_uri[:path_start]
            request_uri = remainder_uri[path_start:]
            host = host_and_port[:path_start]
        else:
            host_and_port = remainder_uri
            request_uri = SLASH
            host = host_and_port

        var scheme: String
        if is_https:
            scheme = HTTPS
        else:
            scheme = HTTP

        var n = request_uri.find("?")
        var original_path: String
        var query_string: String
        if n >= 0:
            original_path = request_uri[:n]
            query_string = request_uri[n + 1 :]
        else:
            original_path = request_uri
            query_string = ""

        return URI(
            _original_path=original_path,
            scheme=scheme,
            path=original_path,
            query_string=query_string,
            _hash="",
            host=host,
            full_uri=uri,
            request_uri=request_uri,
            username="",
            password="",
        )

    fn __init__(
        out self,
        uri: String = "",
    ):
        self._original_path = "/"
        self._hash = ""
        self.scheme = ""
        self.path = "/"
        self.query_string = ""
        self.host = ""
        self.full_uri = uri
        self.request_uri = ""
        self.username = ""
        self.password = ""

    fn is_https(self) -> Bool:
        return self.scheme == HTTPS

    fn is_http(self) -> Bool:
        return self.scheme == HTTP or len(self.scheme) == 0

    fn is_wss(self) -> Bool:
        return self.scheme == WSS

    fn get_path(self) -> String:
        # TODO: Remove try-catch when .format() does not raise
        if self.query_string:
            try:
                return "{}?{}".format(self.path, self.query_string)
            except e:
                pass
        return self.path

    fn _parse(mut self) raises -> None:
        var raw_uri = self.full_uri
        var proto_str = String(HTTP)
        var is_https = False

        var proto_end = raw_uri.find("://")
        var remainder_uri: String
        if proto_end >= 0:
            proto_str = raw_uri[:proto_end]
            if proto_str == HTTPS:
                is_https = True
            remainder_uri = raw_uri[proto_end + 3:]
        else:
            remainder_uri = raw_uri

        self.scheme = proto_str

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

        var n = request_uri.find("?")
        if n >= 0:
            self._original_path = request_uri[:n]
            self.query_string = request_uri[n + 1 :]
        else:
            self._original_path = request_uri
            self.query_string = String()

        self.path = self._original_path
        self.request_uri = request_uri

    fn get_hostname(self) -> String:
        """
        Returns the hostname of the URI.
        """
        var i = max(0, self.host.find("@"))
        j = self.host.find(":")
        if j < 0:
            j = len(self.host)

        return self.host[i: j]

    fn get_port(self) raises -> Int:
        """
        Returns the port of the URI.
        """
        # Ignore the potential username and password
        var i = max(0, self.host.find("@"))
        var j = self.host.find(":", start=i)
        if j < 0:
            return 443 if self.is_https() or self.is_wss() else 80
        return Int(self.host[j + 1 :])

    fn get_user_info(self) -> Optional[(String, String)]:
        """
        Returns the username and password of the URI.
        """
        var i = self.host.find("@")
        if i < 0:
            return None

        user_info = self.host[:i]
        try:
            result = user_info.split(":", maxsplit=2)
            return (result[0], result[1])
        except:
            return (user_info, String(""))

