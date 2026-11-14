# crash class `asan-legacy_read_len-36724563`

- fingerprint: `asan:legacy_read_len@legacy_tlv.c:60:57|legacy_parse_scope@legacy_tlv.c:119:13|legacy_parse@legacy_tlv.c:198:13`
- sanitizer: asan
- report detail: heap-buffer-overflow on address 0x60200000019f at pc 0x000100c025e4 bp 0x00016f1fe0d0 sp 0x00016f1fe0c8
- frames: legacy_read_len@legacy_tlv.c:60:57 <- legacy_parse_scope@legacy_tlv.c:119:13 <- legacy_parse@legacy_tlv.c:198:13 <- LLVMFuzzerTestOneInput@fuzz_legacy.c:21:11 <- start+0x1fdfc <- _Znam+0x65570 <- start+0x1fdfc
- artifacts in class: 1 (1 live, 0 stale)
- representative: `crash-23802ecc70f0a68a70f9433205521955d54cf380` (sha256 ee8c0209e4f2ec5c..., 15 bytes)
- minimized sample: `corpus/regression/asan-legacy_read_len-36724563.tlv` (15 bytes, down from 15)

## reproducer

```sh
$(BINARY) corpus/regression/asan-legacy_read_len-36724563.tlv
```

## members

- `crash-23802ecc70f0a68a70f9433205521955d54cf380` sha256=ee8c0209e4f2ec5c reproduces=yes
