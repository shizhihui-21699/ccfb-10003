# crash class `assert-legacy_decode_value-97d44ecd`

- fingerprint: `assert:legacy_decode_value@legacy_tlv.c:80:16|legacy_parse_scope@legacy_tlv.c:145:13|legacy_parse@legacy_tlv.c:198:13`
- sanitizer: assert
- report detail: deadly signal
- frames: legacy_decode_value@legacy_tlv.c:80:16 <- legacy_parse_scope@legacy_tlv.c:145:13 <- legacy_parse@legacy_tlv.c:198:13 <- LLVMFuzzerTestOneInput@fuzz_legacy.c:21:11 <- start+0x1fdfc
- artifacts in class: 1 (1 live, 0 stale)
- representative: `crash-913886b4c6b976afc5e45b6576e9dfd49f62b5a1` (sha256 a295765d451b5efa..., 1040 bytes)
- minimized sample: `corpus/regression/assert-legacy_decode_value-97d44ecd.tlv` (1040 bytes, down from 1040)

## reproducer

```sh
$(BINARY) corpus/regression/assert-legacy_decode_value-97d44ecd.tlv
```

## members

- `crash-913886b4c6b976afc5e45b6576e9dfd49f62b5a1` sha256=a295765d451b5efa reproduces=yes
