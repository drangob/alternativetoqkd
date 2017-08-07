# WireGuard integration

Some level of WireGuard integration has been achieved via using an additional 
kernel module character device which is used to essentially pipe random bits 
from the userspace implementation of our solution to the WireGuard kernel 
module.  

At this moment the implementation involves WireGuard pulling keys from the 
character device whenever it seeks to complete a handshake. Using semaphores,
this is replenished by the userspace random bit consumption system.

## Issues
When a handshake fails in WireGuard it simply retries the handshake a second or
so later. This means that keys are consumed very quickly by the handshake 
initiator if the respondant is not online and availible, causing a 
desynchronisation which causes the system to break down.  
A system must be built into WireGuard at a different level therefore in order to 
distinguish between retries and new handshakes to fix desync issues.
