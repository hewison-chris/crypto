/*******************************************************************************

    Define the types used by this library

    This module is separate from `agora.crypto.Hash` and others to allow
    lightweight imports in client code, as well as to embbed a `Hash` into
    a `struct` without adding a dependency to the hashing code.

    Copyright:
        Copyright (c) 2019 BOS Platform Foundation Korea
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.crypto.Types;

import geod24.bitblob;

/// 512 bits hash type computed via `BLAKE2b`
public alias Hash = BitBlob!512;

/// The type of a signature
public alias Signature = BitBlob!512;

unittest
{
    // Check that our type match libsodium's definition
    import libsodium;

    static assert(Signature.sizeof == crypto_sign_ed25519_BYTES);
    static assert(Hash.sizeof == crypto_generichash_BYTES_MAX);
}

/// Describe print modes for `toString`
public enum PrintMode
{
    /// Print hidden version
    Obfuscated,
    /// Print original value
    Clear,
}
