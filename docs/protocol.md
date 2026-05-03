# Wire protocol

## Frame format

```
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-------------------------------+-------+-----------------------+
|         length (BE 32)        | type  |  seq_num (BE 64) ...  |
+-------------------------------+-------+                       |
|                          ... seq_num ...                      |
+---------------------------------------------------------------+
|                            payload                            |
:                              ...                              :
+---------------------------------------------------------------+
```

- `length`: number of bytes following the length field, i.e. `1 + 8 + len(payload)`.
- `type`: message type, one byte:

| Code | Name      | Direction          | Payload                                                    |
|------|-----------|--------------------|------------------------------------------------------------|
| 0x01 | HELLO     | initiator → responder | `sig_pk_i || nonce_i (16B)`                             |
| 0x02 | HELLO_ACK | responder → initiator | `sig_pk_r || kem_pk || nonce_r (16B) || sig_r`           |
| 0x03 | KEM_CT    | initiator → responder | `kem_ct || sig_i`                                         |
| 0x04 | DATA      | both directions       | AES-256-GCM(`ct || tag`); AAD = `type || seq`              |
| 0x05 | CLOSE     | both directions       | AES-256-GCM(`ct || tag`); AAD = `type || seq`              |

`seq_num` is meaningful only for DATA / CLOSE; it is 0 for handshake frames.

## Handshake state machine

```
     INITIATOR                                  RESPONDER
   ─────────────                              ─────────────
                                              gen sig keypair
   gen sig keypair
   nonce_i ← rand(16)
   ── HELLO(sig_pk_i, nonce_i) ───────────►   peer_sig_pk_i := sig_pk_i
                                              gen kem keypair (eph)
                                              nonce_r ← rand(16)
                                              sig_r := SIGN_sk_r(
                                                  sig_pk_r || kem_pk
                                                  || nonce_r || nonce_i)
   ◄── HELLO_ACK(sig_pk_r, kem_pk,
                   nonce_r, sig_r) ─────────
   verify sig_r  ── if BAD → abort
   peer_sig_pk_r := sig_pk_r
   (kem_ct, ss) := KEM_ENCAPS(kem_pk)
   sig_i := SIGN_sk_i(kem_ct
                       || nonce_i || nonce_r)
   ── KEM_CT(kem_ct, sig_i) ──────────────►   verify sig_i ── if BAD → abort
                                              ss := KEM_DECAPS(kem_ct, kem_sk)

   derive(k_i2r, k_r2i, salt_i2r, salt_r2i)   derive(...)
   send_seq := 0; recv_window := empty        send_seq := 0; recv_window := empty
                  ──── application DATA frames ────►
                  ◄─── application DATA frames ─────
                  ──── CLOSE ────►
```

## Key derivation

```
salt = nonce_i || nonce_r                         (32 bytes)
info = "pq-secure-comm v1"
out  = HKDF-SHA256(IKM=ss, salt=salt, info=info, L=72)
  k_i2r    = out[ 0..32]
  k_r2i    = out[32..64]
  salt_i2r = out[64..68]
  salt_r2i = out[68..72]
```

## AEAD framing

Each DATA / CLOSE frame uses a fresh AES-256-GCM nonce:

```
nonce = direction_salt (4B) || seq_num (8B BE)        (12 bytes total)
AAD   = msg_type (1B) || seq_num (8B BE)              (9 bytes)
```

`AAD` binds both the message type and the sequence number into the GCM
authentication tag. Any attacker who flips a bit in the ciphertext, swaps the
type byte, or replays a frame at a different sequence number causes
GCM verification to fail.

The 4-byte salt is unique per direction, so initiator and responder will never
generate the same `(key, nonce)` pair even if their `seq_num` counters happen to
align.

## Replay defense

A 64-entry sliding-bitmap window per direction (RFC 4303 §3.4.3 style):

- Track `highest`, the largest seq seen so far.
- Track a 64-bit bitmap of which of the last 64 seqs have been received.
- A frame with `seq > highest` shifts the bitmap left and is accepted.
- A frame with `highest - seq < 64` is accepted iff its bit is currently 0.
- A frame with `highest - seq ≥ 64` is rejected as too old.

## Security properties

| Property                 | How it's achieved                                                                                  |
|--------------------------|----------------------------------------------------------------------------------------------------|
| Confidentiality          | AES-256-GCM under HKDF-derived keys; KEM provides forward-secret session secret per handshake.     |
| Integrity (per frame)    | GCM tag covers ciphertext + AAD; flipping a bit fails verification.                                 |
| Peer authentication      | Each side signs handshake transcript chunks with its long-term PQ signature key.                    |
| Replay resistance        | Per-direction sliding window over `seq_num`; AAD binds `seq_num` into each ciphertext.              |
| Transcript binding       | Both signatures cover the two nonces, binding initiator's and responder's contributions together.   |
| Forward secrecy          | Responder uses an *ephemeral* KEM keypair; long-term keys are signature-only.                       |
| KCI / role confusion     | Per-direction keys + role-aware derivation prevent reuse across directions.                         |

## Caveats

- This is research-grade code. It has not been formally verified, side-channel
  hardened, nor independently reviewed. Do not deploy as-is.
- `liboqs` itself is not constant-time on all platforms for all algorithms — see
  the upstream security policy.
