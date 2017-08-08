# WireGuard integration

Some level of WireGuard integration has been achieved via using an additional 
kernel module character device which is used to essentially pipe random bits 
from the userspace implementation of our solution to the WireGuard kernel 
module.  

WireGuard pulls keys from the character device when it is either initiating a 
connection, or consuming an initiation from another peer. This is only done on 
the first attempt in case of packets failing to arrive and causing 
desyncronisation between peers.  

The character device /dev/wgchar uses semaphores to enable the userspace key
replenishment system to loop feeding new keys to WireGuard. The character device
can only be read by a kernel mode program.

## Current issues
As we only solve the issue of the initiation packet being sent with the right 
key, there is no way to distinguish whether the handshake response is a retry or
not, therefore it will keep trying to use new keys, thinking each handshake 
retry is unique.  
This means that if a handshake response fails to be sent, the system will become
desyncronised.

## Previous Issues
When a handshake failed in WireGuard it simply retries the handshake a second or 
so later. This means that keys are consumed very quickly by the handshake 
initiator if the respondant is not online and availible, causing a 
desynchronisation which causes the system to break down.  
A system must be built into WireGuard at a different level therefore in order to 
distinguish between retries and new handshakes to fix desync issues.

>Fixed by using the handshake flags in WireGuard to detirmine if it is a first
try or not.


