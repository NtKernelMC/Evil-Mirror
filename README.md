# Evil-Mirror

Research note for a server-side RAGE:MP typed-argument parser flaw. A connected client can make `ragemp-server.exe` copy beyond the end of a received packet when a type `0x18` argument claims more bytes than remain. A server resource that reflects the resulting argument can disclose process memory in its reply.

## Observed impact

The investigated server executable has SHA-256 `268FE59F33F6700508BE40792D5697A7BDD57F887BB8B8F31C55886A14C36A3F`. A controlled test confirmed a single malformed request produced an oversized JavaScript `ArrayBuffer`. On a separately authorized server, a reflecting resource returned 65,535 bytes from a 36-byte request containing eight supplied blob bytes. The returned data included complete HTTP credential and API-secret shaped values. Their current validity was not tested. Two of four identical local maximum-length trials ended in access violations, so a reliable remote crash is not established. Remote code execution has **not** been demonstrated.

No captured memory, credentials, operational packet sender, or internal reverse-engineering report is included in this repository.

## Root cause

The type `0x18` parser reads a 16-bit length and compares it with the bytes left in the packet view. Its conditional branch rejects *shorter* lengths, allowing an oversized length to reach a blob setter that copies the claimed byte count. The copy occurs before event-specific handler lookup.

```asm
; ragemp-server.exe, image VA 0x1412AD4C2
3B D1                   cmp edx, ecx        ; declared length, remaining bytes
0F 82 C0 08 00 00       jb  reject_arg     ; currently rejects len < remaining
```

## Proposed assembly fix — not tested

For an aligned, otherwise valid packet view, change the conditional opcode byte at image VA `0x1412AD4C5` from `82` (`JB`) to `87` (`JA`). The original sequence is `3B D1 0F 82 C0 08 00 00`; the proposed sequence is `3B D1 0F 87 C0 08 00 00`.

```asm
cmp edx, ecx
ja  reject_arg          ; reject declared length > remaining bytes
```

**This one-byte patch has not been applied or runtime tested.** An unaligned bit cursor requires a stronger guard before the copy call at `0x1412AD4EF`. The following Intel-style code is a design sketch for a code cave, not a drop-in patch. Bind `stream` and `declared_len` to the actual live operands at the detour and preserve registers, stack alignment, unwind behavior, and relocated instructions.

```asm
; DESIGN SKETCH ONLY — NOT ASSEMBLED OR TESTED
; BitStream +0: totalBits (u32), +8: cursorBits (u32)
mov   eax, dword ptr [stream + 8]
mov   ecx, dword ptr [stream + 0]
cmp   eax, ecx
ja    reject_arg

mov   r8d, eax
add   r8, 7
shr   r8, 3                    ; byteOffset = ceil(cursorBits / 8)
mov   r9d, ecx
add   r9, 7
shr   r9, 3                    ; viewBytes = ceil(totalBits / 8)
cmp   r8, r9
ja    reject_arg
sub   r9, r8                   ; available bytes from the copy source
cmp   declared_len, r9         ; use matching widths in the real patch
ja    reject_arg
; Rejoin the original copy path after validating the source range.
```

The final patch must also check that reading the 16-bit length succeeded and that the backing allocation covers the computed view. These offsets apply only to the binary identified above. A server-side resource should separately reject malformed arguments and avoid reflecting untrusted opaque values.

## Maintainer validation

1. Confirm the executable hash and original bytes before patching.
2. Test valid type `0x18` arguments at exact packet boundaries and at the 65,535-byte limit.
3. Under a debugger or memory instrumentation, test truncated inputs with aligned and unaligned cursors. Confirm rejection before any memory copy or JavaScript callback.
4. Check that application responses cannot reflect process memory and that ordinary events still work.

The proposed fix remains **untested**. The demonstrated impact is an out-of-bounds read with conditional information disclosure; code execution has not been shown.
