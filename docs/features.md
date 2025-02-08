
# Features

## Both sides

| Feature                                           | sync | sans I/O |
|----------------------------------------------------|------|---------|
| Perform the opening handshake                      | ✅  | ✅       |
| Enforce opening timeout                            | ❌  | ❌       |
| Send a message                                     | ✅  | ✅       |
| Broadcast a message                                | ❌  | ❌       |
| Receive a message                                  | ✅  | ✅       |
| Iterate over received messages                     | ❌  | ✅       |
| Send a fragmented message                          | ❌  | ✅       |
| Receive a fragmented message frame by frame        | ❌  | ❌       |
| Receive a fragmented message after reassembly      | ❌  | ✅       |
| Send a ping                                        | ✅  | ✅       |
| Respond to pings automatically                     | ✅  | ✅       |
| Send a pong                                        | ✅  | ✅       |
| Keepalive                                          | ❌  | ✅       |
| Heartbeat                                          | —   | ✅       |
| Measure latency                                    | —   | ❌       |
| Perform the closing handshake                      | ✅  | ✅       |
| Enforce closing timeout                            | —   | ❌       |
| Report close codes and reasons from both sides     | ✅  | ❌       |   
| Compress messages (`RFC 7692`)                     | ❌  | ❌       |    
| Negotiate extensions                               | ❌  | ❌       |      
| Implement custom extensions                        | ❌  | ❌       |     
| Negotiate a subprotocol                            | ❌  | ❌       |      
| Enforce security limits                            | ❌  | ❌       |  
| Log events                                         | ✅  | -        |  

#  Server   

| Feature                               | sync | sans I/O |
|---------------------------------------|------|----------|
| Listen on a TCP socket                | ✅   | —        |
| Listen on a Unix socket               | ❌   | —        |
| Listen using a preexisting socket     | ❌   | —        |
| Encrypt connection with TLS           | ❌   | —        |
| Close server on context exit          | ✅   | —        |
| Close connection on handler exit      | ❌   | —        |
| Shut down server gracefully           | ✅   | —        |
| Check ``Origin`` header               | ✅   | ✅       |
| Customize subprotocol selection       | ❌   | ❌       |
| Configure ``Server`` header           | ✅   | ✅       |
| Alter opening handshake request       | ✅   | ✅       |
| Alter opening handshake response      | ✅   | ✅       |
| Force an HTTP response                | ✅   | ✅       |
| Perform HTTP Basic Authentication     | ✅   | ❌       |
| Perform HTTP Digest Authentication    | ❌   | ❌       |

## Client


| Feature                                | sync | sans I/O | 
|----------------------------------------|------|----------|
| Connect to a TCP socket                | ✅   | —        |
| Connect to a Unix socket               | ❌   | —        |
| Connect using a preexisting socket     | ❌   | —        |
| Encrypt connection with TLS            | ❌   | —        |
| Close connection on context exit       | ✅   | —        |
| Reconnect automatically                | ❌   | —        |
| Configure ``Origin`` header            | ✅   | ✅       |
| Configure ``User-Agent`` header        | ❌   | ❌       |
| Modify opening handshake request       | ✅   | ✅       |
| Modify opening handshake response      | ✅   | ✅       |
| Connect to non-ASCII IRIs              | ✅   | ✅       |
| Follow HTTP redirects                  | ❌   | —        |
| Perform HTTP Basic Authentication      | ✅   | ✅       |
| Perform HTTP Digest Authentication     | ❌   | ❌       |
| Connect via HTTP proxy                 | ❌   | —        |
| Connect via SOCKS5 proxy               | ❌   | —        |
