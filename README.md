# WebServer
Networks final project


A web server that supports GET and HEAD requests, accepts command line flags representing the TCP ports to bind to, supports encrypted 
connections via HTTPS using TLS (SSL 3.0), listens simultaneously on HTTP and HTTPS ports using multithreading, and supports persistent 
connections.


To compile and run:
  - "$ make"
  - "$ java Server --serverPort=12345 --sslServerPort=12346" with desired port numbers
  
[Project assignment sheet](https://docs.google.com/document/d/1kcd4XLYgBfvKsHn36wmTkXINDNxswMfSb7OR8FZ8tYA/edit)
