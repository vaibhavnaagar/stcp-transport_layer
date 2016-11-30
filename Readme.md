

# STCP Transport Layer #
>CS425: Computer Networking (Project-3)
						
* It establishes connection between two peers after three way handshake.
* STCP provides a connection-oriented, in-order, full duplex end-to-end delivery mechanism.
* It is similar to early versions of TCP, which did not implement congestion control or optimizations such as selective ACKs or fast retransmit.
* STCP treats application data as a stream i.e., no artificial boundaries are imposed on the data by the transport layer.
* It runs continuously until connection is either closed by peer or by the application itself. In between it waits for events when network packet arrives or application sends some data.
* `transport.c` is the main file in which stcp transport layer is implemented.

### How to use it ###

* Run makefile using command "make" or "make all".
* It creates several execuatble files along with- `server` and `client`.
* Run server using command: 
```sh 
./server 
```
* Run client using command: 
```sh 
./client [-q] [-f <filename>] server:port
```
* To use STCP transport layer, include `"mysock.h"` in the codes. The header file `"mysock.h"` provides various socket relevant functions which is similar to real socket methods.
* See `mysocket.h, mysocket.c, server.c and client.c` for more info. 





