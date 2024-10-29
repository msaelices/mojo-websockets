alias Byte = UInt8
alias Bytes = List[Byte, True]
alias Duration = Int
alias DEFAULT_BUFFER_SIZE = 4096
alias DEFAULT_MAX_REQUEST_BODY_SIZE = 10 * 1024 * 1024  # 10 MB
alias DEFAULT_TCP_KEEP_ALIVE = Duration(15 * 1000 * 1000 * 1000)  # 15 seconds
