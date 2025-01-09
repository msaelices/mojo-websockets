from collections import Dict, List
from testing import assert_equal, assert_true

from websockets.http import (
    HTTPRequest,
    HTTPResponse,
    Header,
    HeaderKey,
    Headers,
    encode,
)
from websockets.utils.uri import URI
from websockets.utils.string import (
    ByteReader,
    Bytes,
    bytes,
    empty_string,
    to_string,
)

alias DEFAULT_SERVER_CONN_STRING = "http://localhost:8080"

fn test_header() raises:
    test_parse_request_header()
    test_parse_response_header()
    test_header_case_insensitive()


fn test_header_case_insensitive() raises:
    var headers = Headers(Header("Host", "SomeHost"))
    assert_true("host" in headers)
    assert_true("HOST" in headers)
    assert_true("hOST" in headers)
    assert_equal(headers["Host"], "SomeHost")
    assert_equal(headers["host"], "SomeHost")


fn test_parse_request_header() raises:
    var headers_str = bytes(
        """GET /index.html HTTP/1.1\r\nHost:example.com\r\nUser-Agent: Mozilla/5.0\r\nContent-Type: text/html\r\nContent-Length: 1234\r\nConnection: close\r\nTrailer: end-of-message\r\n\r\n"""
    )
    var header = Headers()
    var b = Bytes(headers_str)
    var reader = ByteReader(b^)
    var method: String
    var protocol: String
    var path: String
    method, path, protocol = header.parse_raw(reader)
    assert_equal(path, "/index.html")
    assert_equal(protocol, "HTTP/1.1")
    assert_equal(method, "GET")
    assert_equal(header["Host"], "example.com")
    assert_equal(header["User-Agent"], "Mozilla/5.0")
    assert_equal(header["Content-Type"], "text/html")
    assert_equal(header["Content-Length"], "1234")
    assert_equal(header["Connection"], "close")


fn test_parse_response_header() raises:
    var headers_str = bytes(
        """HTTP/1.1 200 OK\r\nServer: example.com\r\nUser-Agent: Mozilla/5.0\r\nContent-Type: text/html\r\nContent-Encoding: gzip\r\nContent-Length: 1234\r\nConnection: close\r\nTrailer: end-of-message\r\n\r\n"""
    )
    var header = Headers()
    var protocol: String
    var status_code: String
    var status_text: String
    var reader = ByteReader(headers_str^)
    protocol, status_code, status_text = header.parse_raw(reader)
    assert_equal(protocol, "HTTP/1.1")
    assert_equal(status_code, "200")
    assert_equal(status_text, "OK")
    assert_equal(header["Server"], "example.com")
    assert_equal(header["Content-Type"], "text/html")
    assert_equal(header["Content-Encoding"], "gzip")
    assert_equal(header["Content-Length"], "1234")
    assert_equal(header["Connection"], "close")
    assert_equal(header["Trailer"], "end-of-message")


fn test_http() raises:
    test_encode_http_request()
    test_encode_http_response()


fn test_encode_http_request() raises:
    var uri = URI(DEFAULT_SERVER_CONN_STRING + "/foobar?baz")
    var req = HTTPRequest(
        uri,
        body=String("Hello world!").as_bytes(),
        headers=Headers(Header("Connection", "keep-alive")),
    )

    var as_str = str(req)
    var req_encoded = to_string(encode(req^))
    assert_equal(
        req_encoded,
        (
            "GET / HTTP/1.1\r\nconnection: keep-alive\r\n"
            "\r\nHello world!"
        ),
    )
    assert_equal(req_encoded, as_str)


fn test_encode_http_response() raises:
    var res = HTTPResponse(200, "OK", Headers(), bytes("Hello, World!"))
    res.headers[HeaderKey.DATE] = "2024-06-02T13:41:50.766880+00:00"
    var as_str = str(res)
    var res_encoded = to_string(encode(res^))
    var expected_full = "HTTP/1.1 200 OK\r\ndate: 2024-06-02T13:41:50.766880+00:00\r\n\r\nHello, World!"

    assert_equal(res_encoded, expected_full)
    assert_equal(res_encoded, as_str)
