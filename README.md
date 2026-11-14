# libtlv

一个按规范重写的 TLVX 二进制协议解析/编码库：长度嵌套、变长整数（LEB128）、
可选字段全部支持；解析器是**迭代式**的，不递归，因此恶意深嵌套不会打爆调用栈。

线格式规范见 [`docs/PROTOCOL.md`](docs/PROTOCOL.md)（规范性文件，用例即其可执行版本）。
崩溃汇总见 [`docs/CRASHES.md`](docs/CRASHES.md)，fuzzing 与处置链路见
[`docs/FUZZING.md`](docs/FUZZING.md)，验收数据见 [`docs/RESULTS.md`](docs/RESULTS.md)。

## 快速开始

```sh
brew install llvm        # 需要带 -fsanitize=fuzzer 的 compiler-rt
make test                # 416 项一致性用例，ASan+UBSan
make fuzz                # 10 分钟 libFuzzer，含去重/最小化/归类
make fuzz-check          # 回归语料重放 + 60 秒冒烟（CI 用）
```

`make` 会自动优先 `/opt/homebrew/opt/llvm/bin/clang`；Apple CLT 的 clang 缺
libFuzzer 运行时。

## API 概览

```c
#include "tlv.h"

tlv_document *doc = NULL;
tlv_error err = tlv_parse_strict(buf, len, &doc);
if (err != TLV_OK) {
    fprintf(stderr, "rejected: %s\n", tlv_strerror(err));
    return;
}

const tlv_node *root  = tlv_document_root(doc);
const tlv_node *inner = tlv_node_child(root, 1);         /* tag 1 */
const tlv_node *name  = tlv_node_child(inner, 2);        /* tag 2 */
const char *s; size_t n;
if (tlv_node_get_string(name, &s, &n) == TLV_OK) { /* ... */ }

tlv_document_free(doc);   /* 只在这里释放 */
```

生命周期（详见 `include/tlv.h`）：

- 所有节点由 document 持有的 arena 分配；**唯一的释放点**是 `tlv_document_free`。
- 值字节不复制，直接指向调用方的输入缓冲区。调用方负责保证缓冲区在 document
  存活期间有效。
- 解析失败时 `*out_doc` 保持 `NULL`，中间分配全部回收，无部分泄漏。

## 设计要点（对应旧实现的崩溃）

| 防线 | 位置 |
|------|------|
| 迭代式作用域栈，深度受限（默认 16，硬上限 64） | `src/tlv_parse.c` |
| 所有长度/偏移读写前先做 `end - p` 边界检查 | `src/tlv_parse.c:read_length` |
| 值零拷贝，变长整数宽度上限 8 字节 | `src/tlv_parse.c`、`src/tlv_varint.c` |
| 节点 arena 所有权，无悬垂指针 | `src/tlv_arena.c` |
| 字段数、总节点数、消息大小全部可配置限流 | `src/tlv_parse.c:tlv_options_normalize` |
| UTF-8 严格校验（RFC 3629：拒绝 overlong/代理区/>U+10FFFF） | `src/tlv_varint.c:tlv_utf8_check` |
| 独立编码器，与解析器互为对照 | `src/tlv_writer.c` |

## 目录

```
include/tlv.h        公共 API
src/                 解析器、查询、编码器、变长整数、arena
tests/test_tlv.c     一致性/边界用例
fuzz/fuzz_tlv.c      libFuzzer harness（重写实现）
fuzz/fuzz_legacy.c   libFuzzer harness（参考夹具，预期崩溃）
legacy/              参考夹具：重建的旧实现，不参与发布
tools/gen_seed.py    种子语料生成器（与 C 编码器独立实现）
tools/triage.py      重放 / 指纹归类 / 最小化 / 入库 / 报告
corpus/seed/         手工+生成的种子
corpus/regression/   按类归档的最小崩溃样本
docs/                协议规范、fuzzing、崩溃汇总、验收结果
```

## 关于 `legacy/`

原始库的源码没有随任务提供。`legacy/legacy_tlv.c` 是按这类手写解析器典型翻车
方式重建的**参考夹具**，只用于给 fuzzing 流水线提供真实缺陷、并把每类崩溃映射到
`src/` 里的具体防线。它不是原始库，也不参与任何发布构建。拿到原始库后，把
`Makefile` 的 `fuzz-legacy` 目标指向它即可，`tools/triage.py` 无需改动。
