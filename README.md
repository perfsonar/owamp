# Trying to provide solutions to improve NAT/PAT Bypass : 
##TWAMP, twping :
- option [Z] was already implemented to set Session Sender/Reflector IP to Zero Addr in Twamp 
Requests from Control-Client. In that case, Control-Client is also Session-Sender and 
Control-Server is Session-Reflector. Control-Server had then to switch the Zero Addr with 
the corresponding Control IP Addr.
Such option is still available but now also split in 2 options : [X] For Session-Sender, 
[Y] For Session-Reflector. 
It helps to bypass NAT on both Session Sender/Reflector when they are also Control Client/Server. 
- Option [y] to handle PAT from the Session-Reflector. In that case, Session-Reflector Port 
is not checked.     
                
## OWAMP: owping : 
- Option [X], [Y] has been added as an extension to OWAMP RFC when Session Sender/Receiver are
also Control Client/Server. 
As for TWAMP, it permits to set Session Sender/Receiver IP to Zero Addr in Owamp Requests
from Control-Client : [X] For Session-Sender, [Y] For Session-Server. 
In that case Control-Server had to switch the Zero Addr with the corresponding Session IP Addr
according the way test is done. For example when tests are done in both ways using Owamp, option [X] 
tells the Control-Server to use the zero address for Control-Client in test session from Control-Client
to Control-Server and for Control-Server in test session from Control-Server to Control-client
It helps to bypass NAT on both Session Sender/Receiver. 
- Option [y] to handle PAT from the Session-Remote. In that case, Session-Remote Port 
is not checked.     
               
## twampd :
- Option [W] : has to be used now to handle Zero Addr in Twamp Request when Session Sender/Reflector 
are also Control Client/Server. Control-Server had then to switch the Zero Addr with 
the corresponding Control IP Addr.
It helps to bypass NAT on both Session Sender/Reflector when they are also Control Client/Server. 
- Option [x] to handle PAT from the Session-Sender. In that case, Session-Sender Port 
is not checked. Indeed, even with Zero Address, PAT on Session-Sender was not considered.     
- Option [Y] : Such option may be used if Control-Client is not aware of NAT on Session-Reflector Side and/or 
does not use zero address. In that case any Session-Reflector Address is seen as Local Address.
                
##  owampd : 
- Option [W] has been added as an extension to OWAMP RFC when Session Sender/Receiver are
also Control Client/Server.  
As for TWAMP, it permits to handle Zero Addr for Session Sender/Receiver in Owamp Requests
from Control-Client 
In that case Control-Server had to switch the Zero Addr with the corresponding Session IP Addr
according the way test is done.  
It helps to bypass NAT on both Session Sender/Receiver. 
- Option [x] to handle PAT from the Session-Remote. In that case, Session-Remote Port 
is not checked. Indeed, even with Zero Address, PAT on Session-Remote was not considered.     
- Option [Y] : Such option may be used if Control-Client is not aware of NAT on Session-Local Side and/or 
does not use zero address. In that case any Session-Local Address is seen as Local Address.
 
 
# DSCP On Control Session:
## owping/twping
Add an option [m] to set DSCP field on Control packets (from Control Client to Server).
To reflect ToS received from Control-Client, on Linux we may have to set 1 into 
/proc/sys/net/ipv4/tcp_reflect_tos on Control-Server side 

