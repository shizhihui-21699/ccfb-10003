# 崩溃汇总

本文件记录 fuzzing 流水线实际发现的每一类崩溃：栈指纹、根因、崩溃样例、
以及在重写实现 `libtlv` 中对应的修复位置。

## 方法论与一个必须说清楚的前提

组里原来的解析库没有随任务提供，本仓库里也不存在它的源码。为了不让“每类崩溃的
根因 / 修复位置 / 最小样本”三项空着，仓库包含一个**参考夹具**
[`legacy/legacy_tlv.c`](../legacy/legacy_tlv.c)：按照这类手写解析器最典型的翻车方式
重建的旧实现（递归无深度上限、定长栈缓冲、未校验长度的指针运算、`free` 后仍被引用的
子节点数组等）。它**不是**原来的库，也**不**参与 `libtlv` 的构建和发布；它只用于：

1. 给流水线提供真实缺陷，证明去重 / 最小化 / 归类确实工作；
2. 把每个崩溃类映射到 `src/` 中具体的一条防线，作为“修复位置”的可验证证据。

若后续拿到原始库，把 `make fuzz-legacy` 的 `$(BUILD)/fuzz_legacy` 目标换成
“原始库 + 同样的 harness”即可，`tools/triage.py` 不需要任何改动。

## 如何复现本报告

```sh
make build/fuzz_legacy
./build/fuzz_legacy -artifact_prefix=build/legacy-crashes/ \
    -max_len=8192 -max_total_time=240 -fork=4 -ignore_crashes=1 corpus/seed
python3 tools/triage.py --crashes build/legacy-crashes \
    --binary build/fuzz_legacy \
    --regression corpus/regression --artifacts artifacts
```

`corpus/seed` 里 17 个由 `tools/gen_seed.py` 独立生成的合法消息足以触发全部 4 类。
本轮共产出 **6584 个 artifact，去重后 4 类**。

每个崩溃都用两个二进制各跑了一遍：

| 二进制 | 期望 |
|--------|------|
| `build/fuzz_legacy`（旧实现） | 崩溃 |
| `build/fuzz_tlv`（重写实现） | 不崩溃（输入被作为普通数据拒绝或接受） |

---

## 类 1：子节点数组 free 后仍被遍历（堆 UAF）

- **指纹**：`asan:legacy_count@legacy_tlv.c:221:28|legacy_count@legacy_tlv.c:223:22`
- **sanitizer**：AddressSanitizer，`heap-use-after-free`
- **artifact 数**：6581（这一类最简单、最容易被变异命中，因此占比压倒性）
- **崩溃点**：`legacy_count` 递归遍历 `node->first_child[i]`
- **根因**：`legacy_parse_scope` 在返回前 `free(children)`，却把指向该数组的
  `out->first_child` 和 `child_count` 保存在父节点里。只要有 ≥1 个子字段，父节点就
  握着悬垂指针，消费方第一次 `legacy_count` 即读已释放内存。
- **最小样本（15 字节）**：

  ```
  54 4c 56 58 01 01 00 00 00 00 04 01 00 00 00
  ```

  `TLVX` + version 1 + flags 0x0100 + `field_region_len = 4`；字段区
  `01 00 00 00` = 位图 `0x01`、tag `0x00`、type `0x00`（INT）、len `0x00`。
  解析器 `calloc` 出 64 个节点的数组、登记 1 个零长子字段，返回前把它 `free`
  掉，消费方一遍历就命中悬垂指针。
- **重写实现的修复位置**：
  - `src/tlv_arena.c` — 节点全部由 document 持有的 arena 分配，解析结束时才统一释放；
    单个 scope 绝不 `free` 自己的节点，从结构上消灭悬垂指针。
  - `src/tlv_query.c:tlv_document_find` — 遍历过程中只解引用 arena 内的节点。
  - 生命周期在 `include/tlv.h` 里明确写下：值字节借用调用方缓冲区，节点归
    document 所有，`tlv_document_free` 是唯一释放点。

## 类 2：三字节长度形式的第一个越界读（heap-buffer-overflow）

- **指纹**：`asan:legacy_read_len@legacy_tlv.c:60:57`
- **sanitizer**：AddressSanitizer，`heap-buffer-overflow`（READ）
- **artifact 数**：1
- **崩溃点**：`legacy_read_len` 三字节分支 `(b0 & 0xF0) == 0xC0`，表达式
  `(uint32_t)p[*pos] << 8` 这一列（第 57 列）
- **根因**：进入三字节分支后直接读 `p[*pos]`，没有先确认 `b0` 之后还有 2 字节。
- **最小样本（15 字节）**：

  ```
  54 4c 56 58 01 00 00 00 00 00 04 de 2a be cf
  ```

  `field_region_len = 4`，字段区 `de 2a be cf`：位图 `0xDE`、tag `0x2A`、
  类型 `0xBE`、长度首字节 `0xCF`（`0xC0|0x0F`，三字节形式）。`pos` 此时已在
  输入尾部，`p[*pos]` 越过缓冲区最后一字节。
- **重写实现的修复位置**：
  - `src/tlv_parse.c:read_length` — 每个多字节形式先算 `end - p` 是否够，
    不够返回 `TLV_ERR_TRUNCATED`；所有读取都以 `fr->end` 为硬边界。
  - 该函数的每个 `buf[p++]` 都发生在长度检查之后。

## 类 3：三字节长度形式的第二个越界读（heap-buffer-overflow）

- **指纹**：`asan:legacy_read_len@legacy_tlv.c:60:72`
- **sanitizer**：AddressSanitizer，`heap-buffer-overflow`（READ）
- **artifact 数**：1
- **崩溃点**：同一行的 `p[*pos + 1]`（第 72 列）
- **根因**：与类 2 同一表达式里的两次读取，但**越界的是另一个字节**：
  类 2 在 `p[*pos]` 处（`pos` 已在尾部），类 3 在 `p[*pos]` 合法、`p[*pos+1]`
  越界。它们是同一函数、同一行上的两个独立缺陷，所以指纹必须到列级：
  地址/行号级指纹会把它们合并成一个，掩盖“只修了第一个读”这种半吊子修复。
- **最小样本（16 字节）**：

  ```
  54 4c 56 58 01 00 00 00 00 00 05 00 01 40 c7 01
  ```

  `field_region_len = 5`，字段区 `00 01 40 c7 01`：位图 0、tag 1、type `0x40`
  （BOOL）、长度首字节 `0xC7`（三字节形式）。`p[*pos]` 取到 `0x01`，`p[*pos+1]`
  越过输入末尾。
- **重写实现的修复位置**：同 `src/tlv_parse.c:read_length`，
  `if (end - p < 2) return TLV_ERR_TRUNCATED;`。

## 类 4：定长栈缓冲被攻击者长度写越界（UBSan → 栈溢出）

- **指纹**：`assert:legacy_decode_value@legacy_tlv.c:80:16`
- **sanitizer**：UBSan 先报
  `index 256 out of bounds for type 'uint8_t[256]'`，随后 `-fno-sanitize-recover`
  触发 abort（libFuzzer 记为 deadly signal）
- **artifact 数**：1
- **崩溃点**：`legacy_decode_value` 的 `tmp[i] = value[i]`，`i` 走到 256
- **根因**：`uint8_t tmp[256]` 却用字段声明长度 `len` 做循环上界，`len` 完全来自
  报文。这是“字段都很小”的经验假设被一个 0x0100+ 长度击穿。
- **样本（1040 字节）**：`docs/samples/class4-stack-overflow.tlv`。这一类的最小化
  会**漂移到类 1**（更小且同样崩溃），因此 triage 拒绝该最小化结果并回退到能复现
  **本类**的最小原始 artifact——这是流水线里“最小化不得改变崩溃类别”的规则。
- **重写实现的修复位置**：
  - 重写实现**不复制值字节**：`tlv_node.value` 直接指向调用方缓冲区，长度由
    `value_len` 精确记录，不存在“解码到临时缓冲”这一步。
  - `src/tlv_varint.c:tlv_uleb_decode / tlv_sleb_decode` 接受 `(p, n)` 切片，且
    `n == 0 || n > 8` 直接返回 `TLV_ERR_VALUE`，从入口就拒绝超宽整数。

---

## 三类“通用”缺陷：流水线抓到过，但在参考夹具里没有单独成类

这些类在**真实流水线运行**中也出现过（见 `docs/FUZZING.md` 的“harness 自身的缺陷”
小节）。它们不是库的缺陷，但同样说明了为什么归类要在指纹里保留行号：

| 缺陷 | 现象 | 处置 |
|------|------|------|
| 用 `strlen` 读非 NUL 结尾的值切片 | ASan `heap-buffer-overflow` in `strlen` ← `tlv_writer_string` | API 增加 `tlv_writer_string_n(w, tag, s, len)`；`tlv_writer_string` 退化为对 NUL 结尾串的便捷包装 |
| 重建树时丢失 `is_optional` | harness 断言失败（重建后 optional 标志与原文不符） | 补 `tlv_writer_{i64,bool,string,skip}_opt`，让每种 kind 都能带可选槽位 |
| 宽松模式的非规范 varint 重建后字节不同 | harness 断言失败 | 比较改为按**语义值**比较，只有严格模式才要求字节级一致 |

## 修复位置总览

| 崩溃类 | 旧实现缺陷 | 重写实现里的防线 |
|--------|-----------|------------------|
| 1 堆 UAF | 子节点数组提前 `free` | arena 所有权（`src/tlv_arena.c`、`tlv_document_free` 单点释放） |
| 2 长度越界读（2 字节形） | 未检查 `b1` | `read_length` 的 `end - p` 前置检查 |
| 3 长度越界读（3 字节形） | 未检查 `b1/b2` | 同上，`end - p < 2` |
| 4 栈缓冲溢出 | 定长 `tmp[256]` + 攻击者长度 | 值零拷贝 + 变长整数宽度上限 8 字节 |
| （通用）值切片上的 `strlen` | 字符串 API 假设 NUL 结尾 | `tlv_writer_string_n` 显式长度 API |
| （通用）递归无上限 | 递归下降 | 迭代式作用域栈 + `max_depth`（默认 16，硬上限 64） |

## 回归语料

`corpus/regression/` 采用扁平布局（libFuzzer 不递归读子目录），类名作文件前缀：

| 文件 | 类别 | 字节数 |
|------|------|--------|
| `asan-legacy_count-e8f10b71.tlv` | 类 1（堆 UAF） | 15 |
| `asan-legacy_read_len-36724563.tlv` | 类 2（三字节长度首个越界读） | 15 |
| `asan-legacy_read_len-8d94b09d.tlv` | 类 3（三字节长度第二个越界读） | 16 |
| `assert-legacy_decode_value-97d44ecd.tlv` | 类 4（栈缓冲溢出） | 1040 |

同样内容另存档于 `docs/samples/`（带可读文件名）。这 4 个样本在旧实现上必然崩溃
（exit 77/134），在 `build/fuzz_tlv` 上必然 exit 0；`make fuzz-check` 每次重放。
