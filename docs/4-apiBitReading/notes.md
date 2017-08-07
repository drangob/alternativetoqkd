# Bit Consumption

## Pointer incremenation 
If the file we seek to encrypt is bigger than the space, reading the data should
seamlessly pass to the next file on the disk to get more data.

When reading from the bits. we need to calculate where to read up to if we have 
an overflow as in the ptr struct increment we do this by.
offset / filesize = filesfilled
offset % filesize = newoffset 


# Process
- Enter file path, pointer/state path and number of bytes.

- Open the pointer/state file to obtain the place to read from, plus the key k2.
- Get the key from the keyfile to decrypt the file of random bits.

- Load the file into memory and decrypt it.
- Copy the requested decrypted random bits.
- Unload the file from memory.
- Increment the pointer/state file to show where to read from next.
- Use GNU shred (Gutman method) to delete the ciphertext of the random bit file
which has just been read, disables it from being requested twice.

