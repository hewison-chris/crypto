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

This module glues together `ECC` and `Hash` to generate signatures.
In order to generate a signature, both the `Scalar` and the `Point` are used,
so in order to avoid re-generating the `Point` every time, a convenience `Pair` struct is exposed.

The signature generated is stored in a `Sig` structure, however, to separate the chain's data structures
from the crypto code, `Sig` can convert to a `Signature` (see `agora.crypto.Types`) via the `toBlob` method.

The main interface for this module are the various `sign` functions, which can be used in
a pedestrian way (e.g. `Pair kp = Pair.random(); sign(kp, "Message");`), or in a more complex fashion
(using a specific `r`, or even different scalar and points altogether, to allow for multisig schemes).

## [`agora.crypto.Types`](https://github.com/bpfkorea/crypto/blob/v0.x.x/source/agora/crypto/Types.d)

This module exposes types which can be used by client code, without importing the types from other
modules directly (in other words, it's a leaf module).
The aim is to reduce dependencies by allowing a data structure to include a type without gaining
knowledge of the hashing or signing routines.
