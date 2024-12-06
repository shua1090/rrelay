# Computer Security (CSC321) Final Project

A small "relay" in rust. Has an "exposed" (i.e. relay) server
and a "hidden" server. Can probably be used as a method of
NAT "traversal", since hidden server initiates all connections
to the exposed server.

All data between exposed and hidden server is encrypted
after an initial key exchange. Vulnerable to MITM (also
the relay can be used as a MITM too with little modification), but
this is just a survey project so I didn't bother to fix all that. 
Also other connections are "encrypted", but very poorly (0 byte nonce???)
as well.

"System Arch":
![image](https://github.com/user-attachments/assets/a68e938a-e606-4275-bfec-b6a9b52733d9)


Have tested with:
- [X] nc -l 30000
- [X] python3 -m http.server 30000
- [ ] Minecraft Server
