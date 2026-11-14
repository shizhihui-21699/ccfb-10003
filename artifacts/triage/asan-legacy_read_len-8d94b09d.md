# crash class `asan-legacy_read_len-8d94b09d`

- fingerprint: `asan:legacy_read_len@legacy_tlv.c:60:72|legacy_parse_scope@legacy_tlv.c:119:13|legacy_parse@legacy_tlv.c:198:13`
- sanitizer: asan
- report detail: heap-buffer-overflow on address 0x6020000001a0 at pc 0x000104f6a038 bp 0x00016ae960d0 sp 0x00016ae960c8
- frames: legacy_read_len@legacy_tlv.c:60:72 <- legacy_parse_scope@legacy_tlv.c:119:13 <- legacy_parse@legacy_tlv.c:198:13 <- LLVMFuzzerTestOneInput@fuzz_legacy.c:21:11 <- start+0x1fdfc <- _Znam+0x65570 <- start+0x1fdfc
- artifacts in class: 1 (1 live, 0 stale)
- representative: `crash-157d2c1f4313f3ddb9aeb8a509617b9563a7b2e5` (sha256 4448f7d421b73980..., 16 bytes)
- minimized sample: `corpus/regression/asan-legacy_read_len-8d94b09d.tlv` (16 bytes, down from 16)

## reproducer

```sh
$(BINARY) corpus/regression/asan-legacy_read_len-8d94b09d.tlv
```

## members

- `crash-157d2c1f4313f3ddb9aeb8a509617b9563a7b2e5` sha256=4448f7d421b73980 reproduces=yes
