from websockets.net import create_listener


fn main() raises:
    var host_str = '127.0.0.1'
    var port = 8000

    var listener = create_listener(host_str, port)
    print('Listening on ', host_str, ':', port)

    listener.listen()

    while True:
        var conn = listener.accept()
    var conn = listener.accept()
    print('Accepted connection from ', str(conn.raddr))
