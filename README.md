See `eccore.c` and `ectest.c` for realizations of the routines documented in
_Mathematical routines for the NIST prime elliptic curves_.

See `ec256.c` and `ec384.c` for examples of how the routines are used
to generate and verify certificate signatures.

Build and run a demo that does a self test

```
make
./demo
```

NIST P-256 (prime256v1) encrypts 256 bits (32 bytes).
The result is two 32 byte values R and S.

NIST P-384 (secp384r1) encrypts 384 bits (48 bytes).
The result is two 48 byte values R and S.

#

[Mathematical routines for the NIST prime elliptic curves](https://georgeweigt.github.io/nist-routines.pdf)

[certificate-signature.pdf](https://georgeweigt.github.io/certificate-signature.pdf)
