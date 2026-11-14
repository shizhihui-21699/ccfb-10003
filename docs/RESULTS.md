# 验收结果

日期：2026-11-14。平台：macOS 15.5（arm64）、14 核、Homebrew LLVM 23.1.5。

## 1. 单元 / 一致性测试

```
$ make test
505 checks, 0 failures
```

416 → 505 项：新增了长度前缀各个切换边界（127/128、8191/8192、1048575/1048576）
的编码→解析往返用例。全部在 `-fsanitize=address,undefined -fno-sanitize-recover=all`
下运行。

交叉验证（不在 `make test` 里，一次性）：

| 检查 | 用例数 | 不一致 |
|------|--------|--------|
| UTF-8 校验 vs Python `bytes.decode("utf-8")` | 4000 | 0 |
| ULEB128 解码 vs 独立 Python 参考实现 | 3000 | 0 |
| clang 静态分析（`scan-build`） | — | 0 报告 |

## 2. 崩溃处置链路（对参考夹具）

```
$ ./build/fuzz_legacy ... -fork=4 -ignore_crashes=1 -max_total_time=240 corpus/seed
$ python3 tools/triage.py ...
```

| 指标 | 值 |
|------|----|
| 原始 artifact | 6584 |
| 去重后类别 | 4 |
| 最小化后代表样本尺寸 | 15 / 16 / 15 / 1040 字节 |
| 最小化漂移被拒并回退的类 | 2（类 3、类 4） |
| 新实现上重放这些样本 | 全部干净（exit 0） |

明细见 [`CRASHES.md`](CRASHES.md)、`artifacts/triage/summary.json` 与
`corpus/regression/`。

## 3. 十分钟验收 fuzz（按任务要求）

按任务要求跑的是 `make fuzz` 这条正式路径，ASan + UBSan，`-fork=5`，字典
`fuzz/tlv.dict`，种子 `corpus/seed` + `corpus/regression`：

```
$ FUZZ_SECONDS=600 FUZZ_JOBS=5 make fuzz
#983115027: cov: 450 ft: 1888 corp: 353 exec/s: 309497 oom/timeout/crash: 0/0/0 time: 601s
fuzz: no live crashes after 600s
EXIT=0
```

- **9.83 亿次执行**（`-fork=5`，各 job 的进度号之和），**0 崩溃**；崩溃目录为空，
  triage 输出 `no crash artifacts`。
- 覆盖率：**450 条边 / 1888 个特征**（取单 job 峰值；fork 各 job 独立统计）。
- 结束后的回归语料重放：4 个样本、0 崩溃。

交叉验证用的独立跑法（不带字典、`-fork=6`）：

```
#1328864198: cov: 445 ft: 1590 corp: 318 ... oom/timeout/crash: 0/0/0 time: 603s
Done 1328864198 runs in 604s
```

- **13.3 亿次执行，0 崩溃。**

> 注：后一轮（cov 450 / ft 1888）比前一轮（cov 445 / ft 1590）多出的覆盖，来自
> 修掉的一个 **harness** 缺陷：options 原先取自输入前 4 字节，而合法消息的前
> 11 字节被线格式钉死，导致严格模式恒为关、`max_depth` 恒为 12，那条分支从没被
> fuzz 到。详见 `FUZZING.md`。

## 4. 极端输入专项

| 输入 | 结果 |
|------|------|
| `field_region_len = 0xFFFFFFFF`（长度回绕尝试） | `TLV_ERR_TRUNCATED`，无溢出 |
| 100 000 个字段（超出 `max_fields`） | `TLV_ERR_FIELDS` |
| 40 层嵌套、默认 `max_depth=16` | `TLV_ERR_DEPTH` |
| 40 层嵌套、`max_depth=40` | 解析成功、41 个节点 |
| 64 层嵌套（硬上限） | 上限内可解析，不递归、不爆栈 |
| `max_message_bytes` 超限 | `TLV_ERR_LIMIT` |
| 空消息（仅位图字节） | 解析成功、0 个字段 |

## 5. 已知限制

- 原始线上库的源码未随任务提供，`legacy/` 是按典型翻车方式重建的参考夹具
  （详见 `README.md` 与 `CRASHES.md` 开头）。4 类崩溃是**该夹具**的真实缺陷，
  不是对原始库逐 bug 的确认。
- `-fork` 模式下 libFuzzer 按 job 分别统计覆盖率，报告里的 cov 取单 job 峰值而非并集。
- macOS 上 ASan 需要 `ASAN_SYMBOLIZER_PATH` 指向 `llvm-symbolizer` 才有 `file:line`；
  Makefile 与 `tools/triage.py` 已自动处理，手工运行二进制时要自己设。
