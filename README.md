# Crypto

A library to perform cryptographic operations for the BOA blockchain.
The library relies on `libsodium` for cryptographic primitives,
and the `bitblob` package for convenience.

##  [`agora.crypto.Hash`](https://github.com/bpfkorea/crypto/blob/v0.x.x/source/agora/crypto/Hash.d)

This module exposes a thin wrapper on top of `libsodiumd`'s `Blake2b` bindings,
combining it with `bitblob` to provide a more user-friendly experience.
The `Hash` type is a fully `@nogc` value type, and passing it to a string printing
function that supports `toString` sink is guaranteed not to allocate.

## [`agora.crypto.ECC`](https://github.com/bpfkorea/crypto/blob/v0.x.x/source/agora/crypto/ECC.d)

This module exposes thin wrappers on top of `libsodium`'s cryptographic primitives,
allowing to use more convenient syntax (e.g. operator overload) when manipulating scalar
(numbers on finite field, usually used as private keys) and points (usually used as public key).

## [`agora.crypto.Schnorr`](https://github.com/bpfkorea/crypto/blob/v0.x.x/source/agora/crypto/Schnorr.d)

This module glues together `ECC` and `Hash` to generate `Signature`.
TODO MORE.
