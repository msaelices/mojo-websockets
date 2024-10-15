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

1. **Install [Mojo nightly](https://docs.modular.com/mojo/manual/get-started) 🔥**

2. **Add the WebSockets Package** (at the top level of your project):


## TODO

- [ ] Implement WebSocket ping/pong mechanism
- [ ] Optimize performance for high-concurrency scenarios
- [ ] Implement automatic reconnection for clients

## Contributing

Contributions are welcome! If you'd like to contribute, please follow the contribution guidelines in the [CONTRIBUTING.md](CONTRIBUTING.md) file in the repository.

## License

mojo-websockets is licensed under the [MIT license](LICENSE).
