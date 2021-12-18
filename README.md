# Educational AES Implementation

A purely educational (NOT SECURE!) implementation of AES, favouring code readability over performance. 
This is a WIP.

STATE: Basic encryption and decryption for a single block implemented. No block cypher modes for arbitrary lengths of data yet. Only AES128 as of now, AES196 and AES256 will follow as soon as AES128 is completely implemented.

Sources used:
- The NIST AES specification: https://csrc.nist.gov/csrc/media/publications/fips/197/final/documents/fips-197.pdf
- Understanding Cryptography by Christof Paar https://link.springer.com/book/10.1007/978-3-642-04101-3 (Book)
- Supplemental lectures on Christof Paars YouTube channel https://www.youtube.com/channel/UC1usFRN4LCMcfIV7UjHNuQg
- For the key schedule: https://cryptography.fandom.com/wiki/Rijndael_key_schedule
- Reference implementation for debugging: https://www.cryptool.org/de/cto/aes-step-by-step
- Test vectors by NIST https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Block-Ciphers
- Math behind the mix column step: https://www.samiam.org/galois.html
