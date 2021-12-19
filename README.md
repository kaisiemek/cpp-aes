# Educational AES & SHA256 Implementation

> This is a work in progress!

A purely educational (**NOT SECURE!**) implementation of AES, favouring code readability over performance.
Additionally, the SHA256 hash algorithm was implemented as well to generate keys from passwords.
While SHA256 might not be the most conventional choice to generate AES Keys, it is one of the most commonly
used hashing algorithms and given the educational nature of this little project I thought it was a fine choice.

> **Current State**
- Basic Encryption/Decryption of a arbitrary length data (not cleaned up and improved yet)
- SHA256 Hashing of arbitrary bytes, only prototype not cleaned up yet
- Input via command line, prototype
- Not implemented:
  - Variable key length (only AES128 at this point in time)
  - No input/output capabilities, encrypted data and keys are hardcoded arrays
  - No block modes yet (Stuck in simple ECB mode so far)

> **Sources used**
- The NIST AES specification: 
  - https://csrc.nist.gov/csrc/media/publications/fips/197/final/documents/fips-197.pdf
- Understanding Cryptography by Christof Paar: 
  - https://link.springer.com/book/10.1007/978-3-642-04101-3 (Book)
- Supplemental lectures on Christof Paars YouTube channel: 
  - https://www.youtube.com/channel/UC1usFRN4LCMcfIV7UjHNuQg
- For the key schedule:
  - https://cryptography.fandom.com/wiki/Rijndael_key_schedule
- Reference implementation for debugging:
  - https://www.cryptool.org/de/cto/aes-step-by-step
- Test vectors by NIST:
  - https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Block-Ciphers
- Math behind the mix column step:
  - https://www.samiam.org/galois.html
- The NIST Secure Hashing specification (SHA1/2 families):
  - https://csrc.nist.gov/publications/detail/fips/180/4/final
- This amazing video about SHA256:
  - https://www.youtube.com/watch?v=f9EbD6iY9zI
- A great step-by-step breakdown of SHA256, very helpful as validation/test data:
  - https://qvault.io/cryptography/how-sha-2-works-step-by-step-sha-256/
