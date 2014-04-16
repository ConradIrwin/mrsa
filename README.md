This package contains primatives for implementing mediated RSA in golang.

See [https://godoc.org/github.com/ConradIrwin/mrsa](https://godoc.org/github.com/ConradIrwin/mrsa) for docs.

## Mediated RSA

Mediated RSA is a way to split RSA operations amoung multiple parties, none of whom know the entire private key.

It was introduced by D. Boneh, X. Ding, G. Tsudik, and M. Wong in 2001 in their paper
[A Method for Fast Revocation of Public Key Certificates and Security Capabilities](http://crypto.stanford.edu/~dabo/abstracts/sem.html).

## TODO

* RSA blinding across the session.

## Meta-fu

All code is released under a BSD 3-clause license, see LICENSE.BSD for details. Contributions and bug reports welcome.
