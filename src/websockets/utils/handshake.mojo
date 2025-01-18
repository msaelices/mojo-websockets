from base64 import b64encode
from python import Python, PythonObject

from ..aliases import Bytes, MAGIC_CONSTANT


def ws_accept_key(key: String) -> String:
    """
    Generate the accept key for the WebSocket handshake.

    Args:
        key: The key to generate the accept key.

    Returns:
        The accept key.
    """
    var accept_key = key + MAGIC_CONSTANT
    var py_sha1 = Python.import_module("hashlib").sha1

    var encoded_key = py_sha1(PythonObject(accept_key).encode()).digest()
    # TODO: Find a simpler way. The simpler str(encoded_key) is not working
    # of the still poor Mojo support for UTF-8 strings or PythonObject conversion
    # var s = Bytes(capacity=len(encoded_key))
    # for i in range(len(encoded_key)):
    #     s.append(Byte(encoded_key[i]))
    return b64encode(String(encoded_key))
