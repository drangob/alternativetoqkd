# Needed qualities:
- Can access files in a timely manner.
- File sizes are multiples of the file system block size so that no extra space 
is lost. (Would be small anyway, a loss of 4K here or there).
- Layout files in a way which is easy to structurally navigate when consuming 
bits.


# ext4 filesystem:
Built up of 4096byte blocks (can be different but usually not done, block is 
built up of 4 512byte sectors).
Has journalling, this removes all hope of secure deletion, but journal can be 
disabled. 
If we know the name of the file, the performance of accessing that file is not 
lowered by the amount of files around it. 
There is also no limitation to the amount of files in a folder.

## File sizes:
100000000 bytes (100MB) is not a multiple of 4096. Therefore we waste space.
100007936 bytes of space being used for 100000000 bytes of data.
That's almost 1 whole block of wasted data.
Using 100003840 as the desired size creates a file that uses the same 24416 
blocks, the same as previously, but providing 3840 more bytes of data. 

(We can still see that a block has been added to the size of the file- unsure as
to why that extra block exists, filesystem seems to use an extra block when the 
file is over a certain size.)

https://ext4.wiki.kernel.org/index.php/Ext4_Disk_Layout


# Storage Implementation
Write to a disk with 100003840 byte files of random bits. 
Named 0.bin, 1.bin, ... , n.bin

Makes the file system very simple, generate a pointer file with the next file to
be used and the byte offset into that file.
Random file access can be a little expensive (getting from the middle of the 
file), did tests on this which show this  accounts to a 14.675 microsecond 
increase in our system. Therefore no problem.
	
When accessing bits, appropriate bits will be found by following the  pointer to
the file and offset into that file. 
