# Server for Microsoft Messenger 7.0.2
Messenger for Mac OS X not only uses weak ciphers, but also requires the certificate to be issued by Microsoft and by a trusted CA. A custom OpenSSL reenabling weak ciphers is required on the host, as well as a modified Microsoft Messenger executable disabling the certificate restrictions on the client.

While originally believed to be communicating via SSLv2 or TLSv1, it only works with SSLv3 ciphers, allowing for TLSv1 on the server.