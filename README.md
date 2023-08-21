# DLP-Based-Security-Protocols
Implemented various security protocols, schemes and secure random generators assuming Discrete Log Problem as a hard problem.
- **PRG**: Implemented a provably-secure pseudo-random generator. The goal was to create a pseudo-random generator which outputs a pseudo-random bit-string value of length l(k) when the in-class function generate() is invoked.
- **PRF**: Implemented a provably-secure pseudo-random function. The goal was to create a keyed pseudo-random function that outputs a pseudo-random integer value when the particular in class function is evoked.
- **EAV**: Implemented a secure encryption-decryption scheme for an eavesdropping attack.
- **CPA**: Implemented a CPA-secure encryption-decryption scheme using the previously implemented PRF. The goal was to output the ciphertext when the in-class function enc() is invoked and return the plaintext when the in-class function dec() is invoked.
- **MAC**: Implemented a variable-length message authentication code scheme. We were supposed to return the tag when the in-class function mac() is invoked and return a boolean value (0 if the verification is erroneous, 1 otherwise) when the function vrfy() is invoked.
- **CBC-MAC**: Implemented a variable-length CBC-MAC using the previously implemented PRF.
- **CCA**: Implemented a CCA secure scheme using the CPA and CBC-MAC implementations. The goal was to return the cypher text when the in-class function enc() is invoked and return the plain text (or not) when the in-class function dec() is invoked.
