from collections import Optional
from websockets.aliases import Bytes, DEFAULT_BUFFER_SIZE
from websockets.utils.bytes import EOL


trait Streamable:

    fn feed_data(inout self, data: Bytes) raises -> None:
        """
        Write data to the stream.

        `feed_data` cannot be called after `feed_eof`.

        Args:
            data: Data to write.

        Raises:
            EOFError: If the stream has ended.

        """
        ...

    fn feed_eof(inout self) raises -> None:
        """
        End the stream.

        `feed_eof` cannot be called more than once.

        Raises:
            EOFError: If the stream has ended.

        """
        ...

    fn read_line(inout self, m: Int) raises -> Optional[Bytes]:
        """
        Read a LF-terminated line from the stream.

        The return value includes the LF character.

        Args:
            m: Maximum number bytes to read; this is a security limit.

        Raises:
            EOFError: If the stream ends without a LF.
            RuntimeError: If the stream ends in more than ``m`` bytes.
        """
        ...

    fn read_exact(inout self, n: Int) raises -> Optional[Bytes]:
        """
        Read a given number of bytes from the stream.

        Args:
            n: How many bytes to read.

        Raises:
            EOFError: If the stream ends in less than `n` bytes.
        """
        ...

    fn read_to_eof(inout self, m: Int) raises -> Optional[Bytes]:
        """
        Read all bytes from the stream.

        Args:
            m: Maximum number bytes to read; this is a security limit.

        Raises:
            RuntimeError: If the stream ends in more than `m` bytes.
        """
        ...

    fn at_eof(self) -> Bool:
        """
        Tell whether the stream has ended and all data was read.
        """
        ...


@value
struct StreamReader(Streamable):
    """
    Stream reader.
    """
    var buffer: Bytes
    var eof: Bool
    var offset: Int

    fn __init__(out self) -> None:
        self.buffer = Bytes(capacity=DEFAULT_BUFFER_SIZE)
        self.offset = 0
        self.eof = False

    fn feed_data(inout self, data: Bytes) raises -> None:
        """
        Write data to the stream.

        `feed_data` cannot be called after `feed_eof`.

        Args:
            data: Data to write.

        Raises:
            EOFError: If the stream has ended.

        """
        if self.eof:
            raise Error("EOFError: stream ended")
        self.buffer += data

    fn feed_eof(inout self) raises -> None:
        """
        End the stream.

        `feed_eof` cannot be called more than once.

        Raises:
            EOFError: If the stream has ended.

        """
        if self.eof:
            raise Error("EOFError: stream ended")
        self.eof = True

    fn read_line(inout self, m: Int) raises -> Optional[Bytes]:
        """
        Read a LF-terminated line from the stream.

        The return value includes the LF character.

        Args:
            m: Maximum number bytes to read; this is a security limit.

        Raises:
            EOFError: If the stream ends without a LF.
            RuntimeError: If the stream ends in more than ``m`` bytes.
        """
        var n: Int = 0  # number of bytes to read
        var p: Int = 0  # number of bytes without a newline
        var found: Bool = False

        start = self.offset
        for i in range(start, len(self.buffer)):
            if self.buffer[i] == EOL:
                found = True
                n = i + 1
                break
        else:  # no break in the for loop, so not found
            n = len(self.buffer)

        p = n - self.offset
        if p > m:
            raise Error("RuntimeError: read {} bytes, expected no more than {} bytes".format(p, m))
        if not found and self.eof:
            raise Error("EOFError: stream ends after {} bytes, before end of line".format(p))
        if n > m + self.offset:
            raise Error("RuntimeError: read {} bytes, expected no more than {} bytes".format(n, m))

        if not found:
            return None

        result = self.buffer[self.offset:n]
        self.offset = n 

        return result

    fn read_exact(inout self, n: Int) raises -> Optional[Bytes]:
        """
        Read a given number of bytes from the stream.

        Args:
            n: How many bytes to read.

        Raises:
            EOFError: If the stream ends in less than `n` bytes.
        """
        if len(self.buffer) - self.offset < n:
            if self.eof:
                p = len(self.buffer)
                raise Error("EOFError: stream ends after {} bytes, expected {} bytes".format(p, n))
            return None
        result = self.buffer[self.offset: self.offset + n]
        self.offset += n
        return result

    fn read_to_eof(inout self, m: Int) raises -> Optional[Bytes]:
        """
        Read all bytes from the stream.

        Args:
            m: Maximum number bytes to read; this is a security limit.

        Raises:
            RuntimeError: If the stream ends in more than `m` bytes.
        """
        if not self.eof:
            p = len(self.buffer) - self.offset
            if p > m:
                raise Error("RuntimeError: read {} bytes, expected no more than {} bytes".format(p, m))
            return None
        result = self.buffer[self.offset:]
        self.offset = len(self.buffer)
        return result

    fn at_eof(self) -> Bool:
        """
        Tell whether the stream has ended and all data was read.
        """
        if self.offset < len(self.buffer):
            return False
        if self.eof:
            return True
        return False

    fn discard(inout self) -> None:
        """
        Discard all buffered data, but don't end the stream.
    
        """
        self.offset = len(self.buffer)

