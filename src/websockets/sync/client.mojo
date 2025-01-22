from websockets.protocol.client import ClientProtocol
from websockets.utils.uri import URI


struct Client:
    """
    A client object that can be used to connect to a server.
    """
    var protocol: ClientProtocol

    fn __init__(out self, uri: String):
        self.protocol = ClientProtocol(URI.parse(uri))

    fn __moveinit__(mut self, owned other: Self):
        self.protocol = other.protocol^

    fn __copyinit__(mut self, other: Self):
        self.protocol = other.protocol

    fn send(self, data: String) raises -> None:
        """
        Send a message to the server.

        Args:
            data: The message to send.
        """
        # TODO: Implement this method
        pass

    fn recv(self) raises -> String:
        """
        Receive a message from the server.

        Returns:
            String - The message received.
        """
        # TODO: Implement this method
        return "Foo"

    fn close(self) raises -> None:
        """
        Close the connection.
        """
        # TODO: Implement this method
        pass

    # Contex manager methods

    fn __enter__(self) -> Self:
        return self

    fn __exit__(
        mut self,
    ) raises -> None:
        self.close()


fn connect(uri: String) raises -> Client:
    """
    Serve HTTP requests.

    Args:
        uri: The address to connect to.

    Returns:
        Client - A client object that can be used to connect to a server.
    """
    return Client(uri)

