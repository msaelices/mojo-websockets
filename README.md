# mojo-websockets

`mojo-websockets` is a lightweight library for handling WebSocket connections in Mojo. 

It aims to provide an similar interface as the [python-websockets](https://github.com/python-websockets/websockets) package for creating WebSocket servers and clients, with additional features for enhanced usability.

## Disclaimer ⚠️

This software is in a early stage of development, using the Mojo nightly version. Please DO NOT use yet.

## Features

- **WebSocket Server and Client**: Supports creating both WebSocket servers and clients.
- **Asynchronous Communication**: Enables non-blocking WebSocket operations.
- **Compatibility**: API designed to be intuitive for developers familiar with the Python websockets library.

## Installation

1. **Install [magic](https://docs.modular.com/magic#install-magic)**

2. **Add the WebSockets Package** (at the top level of your project):

    ```bash
    magic add websockets
    ```
## Example of usage

```mojo
# TODO
```
## TODO

- [ ] Implement automatic reconnection for clients
- [ ] Get rid of Python dependencies and logic (e.g. no more `from python import ...`)
- [ ] Make sure it passes all the tests in [Autobahn|Testsuite](https://github.com/crossbario/autobahn-testsuite/)
- [ ] Implement subprotocols and extensions
- [ ] Optimize performance for high-concurrency scenarios
- [ ] TLS support

## Contributing

Contributions are welcome! If you'd like to contribute, please follow the contribution guidelines in the [CONTRIBUTING.md](CONTRIBUTING.md) file in the repository.

## Acknowledgments

We have taken a lot of code from the amazing [lightbug_http](https://github.com/saviorand/lightbug_http) project.

Also, we took inspiration and some code from the [python-websockets](https://github.com/websockets) project, specially for implementing the [WebSocket Sans/IO layer](https://websockets.readthedocs.io/en/stable/howto/sansio.html) and their tests.

## License

mojo-websockets is licensed under the [MIT license](LICENSE).
