# Threat Model

## Application
**Random Bit generation application.**  
Invoked by admin/disk creator to fill disks with files.  

**Random Bit consumption application/library.**  
Invoked by users of the random bits to request bits.  

*WireGuard connection kernel module*  
Invoked by local machine administrator to allow data to be fed to WireGuard  

### Dependencies
OpenSSL library  
> AES-CTR  
> AES-GCM  

scrypt library  
> PDKDF  

Linux OS  
> `/dev/random`  
> GNU `shred`  
> WireGuard  

## Entry Points / Assets
1. Random Bit generation application  
2. Random Bit consumption application/library  
3. Random Bit files  
4. State File  
5. Key File  
6. WireGuard connection kernel module  



#### Threats
1. 

2. 

3. *see below*
- Can access the random bits from the file.
  - Bit files are encrypted with AES-CTR mode using key k2.

4. *see below*
- Can modify the state to re-read random bits.
  - State is integrity protected as additional data using AES-GCM with key k1.
- Get key k2 from the state to decrypt the key file.
  - Key k2 is encrypted using AES-GCM with key k1 and nonce of the state.
- Can be decrypted by running dictionary attack on password for derivation of k1
  - Using scrypt for the PDKDF will slow this down.
- Replay old state file to reuse data.
  - When data is read, GNU `shred` is used to ensure that data cannot be reused.

5. *see below*
- Can access the keys to decrypt the random bit files.
  - Each random bit file decryption key in the file is encrypted using AES-GCM 
  with the key k2 and the file number as nonce.

6. *see below*
- Can access the keys while they are in the character device.
  - Character device can only be written to by the userspace. Only readable by a
  kernel space program.  


###### Crypto Chain
`password -> k2 -> keyfile -> random bits `