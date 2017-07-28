# Threat Model
#### Crypto Chain
password -> k2 -> keyfile -> random bits 

### Attacker capability
- Has random bits and keyfile
-- They now have random bits & keys to decrypt them.
-- **Encrypt each line of keyfile to protect random bits, place that key in the state.**
-- Can edit the random bits. **This can be done but aside from denial of service- serves no purpose**.
-- Can edit the keyfile.
-- **Each key in the keyfile is integrity protected**

- Has the state file 
-- Can use the key to decrypt the keyfile
-- **Encrypt the state with a password derived key so that it can be unlocked easily by the user.**
-- Can run a dictionary attack on the password
-- **Using scrypt with a sufficiently high N protects against this**
-- Can edit the pointer to force key reuse
-- **AES-GCM integrity protection is used as the key protection crypto.**
-- Can replay an old pointer to force key reuse
-- **After data is used it is shredded to NULLs using the Gutmann method, meaning data can never be re-used**