# 模糊测试与崩溃处置

## 一句话

`make fuzz` 跑 10 分钟 libFuzzer（ASan + UBSan，`-fno-sanitize-recover`），
每次崩溃都会自动走完“重放 → 栈指纹归类 → 最小化 → 校验不漂移 → 入回归语料 →
生成报告”这条链路；`make fuzz-check` 用回归语料做快速冒烟。

## 工具链

Apple 的 Command Line Tools 里的 clang **不带** `-fsanitize=fuzzer` 的
compiler-rt，链接时会报 `libclang_rt.fuzzer_osx.a not found`。本仓库默认使用
Homebrew LLVM：

```sh
brew install llvm          # 提供 clang 23 + llvm-symbolizer
make fuzz                  # Makefile 自动优先 /opt/homebrew/opt/llvm/bin/clang
```

`tools/triage.py` 会自动探测 `llvm-symbolizer` 并注入 `ASAN_SYMBOLIZER_PATH`，
否则 macOS 上 ASan 只打印裸地址、栈指纹退化、归类失准。

所有构建命令：

```sh
make            # 静态库 build/libtlv.a
make test       # 416 项一致性用例，同样跑在 ASan+UBSan 下
make fuzz       # 10 分钟（FUZZ_SECONDS=... 可改）
make fuzz-check # 回归语料重放 + 60 秒冒烟，适合 CI
make fuzz-legacy   # 对参考夹具跑，产物即 docs/CRASHES.md 的 4 类
make clean
```

## 两个 fuzz 目标

| 目标 | 源 | 用途 |
|------|----|------|
| `build/fuzz_tlv` | `fuzz/fuzz_tlv.c` + `src/` | 被测的**重写实现**；必须长期零崩溃 |
| `build/fuzz_legacy` | `fuzz/fuzz_legacy.c` + `legacy/` | 参考夹具（旧实现）；**预期崩溃**，用来验证处置链路 |

`legacy/` 不参与 `libtlv.a`、不参与 `make test`，只被 `make fuzz-legacy` 使用。

## harness 做了什么

`fuzz/fuzz_tlv.c` 每次执行做四件事，任何一件失败都是崩溃：

1. **解析**：把 fuzzer 输入原样传给 `tlv_parse`。值指针直接指向 fuzzer 自己的
   缓冲区，所以任何越界读都会被 ASan 抓到（不存在“副本缓冲掩盖越界”）。
2. **遍历查询**：迭代式深度优先走遍树，对每种 kind 调用对应 accessor，并对
   值切片的**首尾两个字节**各读一次——长度记账错了立刻触发 ASan。
3. **查找**：对 tag 1..8 调 `tlv_document_find`，覆盖树搜索路径。
4. **重建对照**：用独立的 writer 把树重新编码、再用严格模式解析，按**语义值**
   比较两棵树。这会抓出“编码器和解析器对线格式理解不一致”这类静默损坏。
   宽松模式下的非规范 varint 合法地重建出更短的字节，因此不比较原始字节。

入口还会把输入的**最后 4 个字节**映射成 `tlv_options`（严格模式、`max_depth`、
`max_fields`、`max_total_fields`），让限流分支可被覆盖，而不是只靠专门的语料。

> 这里踩过一个坑，值得记下来：最初用的是**前 4 个字节**。但合法消息的前 11 字节
> 被线格式钉死（magic `TLVX`、version 1、flags、4 字节长度），于是
> `strict = data[0] & 1 = 0x54 & 1 = 0` 恒成立、`max_depth = 0x4C & 0xF = 12`
> 恒定，**严格模式一次都没被 fuzz 到**。改用尾部字节后覆盖率从 445 边升到 450 边、
> 特征从 1585 升到 1621——这就是“harness 本身也要被审视”的具体代价。

## 崩溃处置链路（tools/triage.py）

```
build/crashes/*            （libFuzzer 的 artifact）
   │
   ├─ 1. 并行重放          每个 artifact 单独起进程，并行 8+ 路
   │      rc==0 → 记为 STALE（保留记录，绝不静默丢弃）
   │
   ├─ 2. 分类              sanitizer 类型 + 栈帧
   │      栈帧格式为 `函数@文件:行`（有符号化）或 `函数+偏移`
   │      剥掉 sanitizer/libFuzzer/libc 启动帧，只留我们自己的代码
   │      指纹 = 类型 + 前 3 个帧
   │
   ├─ 3. 每组取一个代表    用 -minimize_crash 最小化（昂贵，只做一次）
   │
   ├─ 4. 漂移校验          重新分类最小化结果；若指纹变了（最小化把
   │                       样本缩成了另一个更小的 bug）→ 拒绝，
   │                       回退到该类别里最小的原始 artifact
   │
   ├─ 5. 入回归语料        corpus/regression/<class>/min-*.tlv
   │
   └─ 6. 报告              artifacts/triage/<class>.md
                           artifacts/triage/summary.json
                           artifacts/triage/INDEX.md
```

两个设计决定值得强调：

- **指纹到行号，不只到函数**。参考夹具里的类 2 和类 3 在同一行、同一表达式
  的两个不同列越界。只用函数名会合并成一类，掩盖“只修了第一个读”的修复。
  实测按 `函数@文件:行` 能稳定分成两类。
- **最小化必须不改变类别**。`-minimize_crash=1` 只保证“还能崩”，不保证“同一个
  bug”。实测中类 4（栈缓冲溢出）的最小化结果漂移成了类 1（更小、同样会崩的
  UAF）。triage 用指纹复检拒绝它并回退，否则回归语料里会躺着一个测错东西的样本。

## 回归语料

```
corpus/seed/                 17 个由 tools/gen_seed.py 独立生成的合法消息
corpus/regression/<class>/   triage 归档的最小样本（按类分目录）
corpus/regression/legacy-ported/  4 个旧实现崩溃样本，跨实现安全回归
```

`corpus/regression/legacy-ported/` 是刻意保留的：这 4 个字节序列在旧实现上必然
崩、在重写实现上必然不崩。它们既是 `docs/CRASHES.md` 的附件，也是防止“以后某次
重构又把边界检查退化掉”的哨兵。`make fuzz-check` 每次重放。

## harness 自身的缺陷（已修，记录在案）

fuzzer 先崩的两次都是 harness 的错，不是库的错——这正是“崩溃要归类到根因”
的意义：

1. 重建树时把值切片交给 `tlv_writer_string`，它内部 `strlen`，而切片并非 NUL
   结尾 → ASan 报 `strlen` 越界。修复：新增 `tlv_writer_string_n(s, len)`，
   `tlv_writer_string` 只作 NUL 串便捷包装。
2. 重建树时没有可选字段的编码 API，丢失 `is_optional` → 重建后的树与原文不符。
   修复：补齐 `tlv_writer_{i64,bool,string,skip}_opt`。
3. 语义比较 vs 字节比较混淆（宽松模式非规范 varint）→ 断言失败。
   修复：按解码值比较，严格模式才比字节。

## 验收标准

任务要求“`make fuzz` 跑十分钟不能再有新崩溃”。验收跑法：

```sh
make fuzz FUZZ_SECONDS=600
```

结果记录在 `docs/RESULTS.md`。
