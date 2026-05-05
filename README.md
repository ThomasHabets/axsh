# axsh

Library and binaries for creating secure yet compliant amateur radio
connections.

Servers and clients have a long term dual sign ML-DSA/ed25519 key, which is
post-quantum safe (with current state of the art fallback). Then for the actual
connection both sides generate a temporary ed25519 key.

## Compliance

Everything sent over the air is clear text. Nothing is encrypted or otherwise
obfuscated. Anyone listening can even confirm that the signature is a signature,
and not some secret communication channel.

And yet they cannot impersonate either side.

## Security

### Authentication (who is the other side?)

The dual signature of ML-DSA/ed25519 provides authentication that the other side
is who you think it is, both with today's ed25519, and protected against quantum
computers with ML-DSA.

ML-DSA has two drawbacks:
1. Keys and signatures are really big. Not suitable for speeds like AX.25
   standard 1200bps. Handshakes take a few seconds.
2. Its core cryptographic primitive is less battle tested. Someone could find a
   flaw. That's what the ed25519 is for.

Authentication is broken if ML-DSA is broken (e.g. by smarter people) AND
ed25519 is broken by a quantum computer. If either happens, we can change it out
and still be protected by the other algorithm.

### Hijack

The bandwidth overhead of ML-DSA signatures is too high to use on every packet.
Therefore the actual payload is secured with only ed25519 signatures.

This means that someone with a quantum computer can hijack a connection already
in progress, if they crack the key during the lifetime of the connection.

A protection against this is to re-key periodically, which is currently not
implemented.

In the future I hope we can replace ed25519 with something both quantum safe and
short.

### Replay

Both sides of every connection create a random unique u64 that is part of every
signature, preventing replay.

TODO: actually, I never did implement that.

## TODO

* Improve protocol by first sending a hash of the connsign key, in case the peer
  has it cached.
* Add unique u64 to every signature.
