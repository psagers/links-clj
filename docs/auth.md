# Authentication

Most client-server communication takes place over a websocket via sente. In
order to establish a connection, the client must already be authenticated,
either directly or through a stored device registration.

The
sente connection is authenticated by the initial HTTP request, which might
include information to authenticate the user and/or the registered device. If
neither are present, the connection is rejected. 
