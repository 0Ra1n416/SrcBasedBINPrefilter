# SrcBasedBINPrefilter

批量预过滤工具 —— 递归扫描文件夹中的二进制文件，对每个文件通过 IDA Pro 反编译 + 启发式分析，计算出 **Source 函数**的数量，最终按数量排序输出 CSV，用于快速筛选潜在攻击面较大的二进制文件。

## 目录

- [环境依赖](#环境依赖)
- [快速开始](#快速开始)
- [命令行参数](#命令行参数)
- [使用示例](#使用示例)
- [输出说明](#输出说明)
- [预过滤机制](#预过滤机制)

## 环境依赖

- **Python** ≥ 3.10
- **IDA Pro**，请配置好环境变量`IDADIR`(Windows)，其他平台请自行查阅
- **ida-pro-mcp**
- Python 包（见 `vulfunc_ranker/requirement.txt`）：

```bash
pip install -r vulfunc_ranker/requirement.txt
```

## 快速开始

```bash
# 基本用法
python bin_pre_filter.py <folder_path>

# 仅统计过滤效果，不实际运行 IDA（建议先跑这个）
python bin_pre_filter.py <folder_path> --dry-run

# 完整运行
python bin_pre_filter.py C:\samples\ --output result.csv --threshold 5
```

## 命令行参数

### `bin_pre_filter.py`

| 参数 | 说明 | 默认值 |
|---|---|---|
| `folder_path` | 要扫描的文件夹路径（必填） | — |
| `--output` | 输出 CSV 文件路径 | `output.csv` |
| `--timeout-output` | 超时文件列表输出路径 | `timeouts.txt` |
| `--threshold` | 只输出 Source 函数数量 ≥ 该阈值的文件 | `0`（输出所有） |
| `-a`, `--absolute` | 使用绝对路径输出 | 关闭（默认相对路径） |
| `-t`, `--timeout` | 每个文件的超时秒数，超时则跳过 | `180` |
| `--min-size` | 最小文件大小（字节），小于则跳过 | `512` |
| `--no-sort` | 不按文件大小升序排列 | 关闭（默认按大小升序） |
| `--no-strict` | 非严格模式：放行未知格式文件 | 关闭（默认严格，跳过未知） |
| `--dry-run` | 仅统计过滤结果，不实际运行 IDA | 关闭 |
| `--resume` | 断点续跑：指定 checkpoint CSV 文件路径 | — |
| `--checkpoint` | Checkpoint CSV 保存路径 | 同 `--resume` |

## 使用示例

```bash
# 基本扫描
python bin_pre_filter.py C:\samples\

# 指定输出文件和阈值
python bin_pre_filter.py C:\samples\ --output result.csv --threshold 5

# 使用绝对路径
python bin_pre_filter.py C:\samples\ -a

# 自定义超时（300 秒）
python bin_pre_filter.py C:\samples\ -t 300

# 不限制超时（不推荐）
python bin_pre_filter.py C:\samples\ -t 0

# 提高最小文件大小阈值（4KB）
python bin_pre_filter.py C:\samples\ --min-size 4096

# 非严格模式（放行未知格式）
python bin_pre_filter.py C:\samples\ --no-strict

# 仅预览过滤效果（推荐先跑）
python bin_pre_filter.py C:\samples\ --dry-run

# 断点续跑
python bin_pre_filter.py C:\samples\ --resume checkpoint.csv
```

## 输出说明

### 输出文件

| 文件 | 内容 |
|---|---|
| `output.csv` | 成功处理的文件路径及 Source 函数数量，按数量降序排列 |
| `timeouts.txt` | 超时被跳过的文件路径列表 |
| `checkpoint.csv` | 断点文件，每处理完一个立即追加，用于续跑 (`--resume`) |

### 处理汇总示例

```
============================================================
[OUT] 二进制文件处理汇总
============================================================
预过滤跳过:       5000
成功处理:         6000
处理出错:         100
处理超时:         50
```

## 预过滤机制

工具在喂给 IDA 之前会做**两层过滤**，减少无效文件的处理时间：

### 第一层：扩展名过滤

跳过已知非二进制文件类型（源码、脚本、文档、图片、压缩包等），共 70+ 种扩展名，包括：

| 类别 | 过滤的扩展名 |
|---|---|
| 脚本/源码 | `.py` `.pl` `.pm` `.sh` `.c` `.cpp` `.go` `.rs` `.rb` `.php` 等 |
| 文本/数据 | `.txt` `.json` `.xml` `.csv` `.log` `.md` 等 |
| 媒体文件 | `.png` `.jpg` `.mp3` `.mp4` 等 |
| IDA 数据 | `.idb` `.i64` `.idc` 等 |
| 其他 | `.zip` `.pdf` `.bak` `.tmp` 等 |
| Perl CGI | `.cgi` `.psgi` `.fcgi` |

### 第二层：内容检测

对第一层放行的文件，读文件头进行检测：

1. **大小阈值**（`--min-size`，默认 512B）—— 过小的文件无法被 IDA 识别
2. **Magic bytes 检测** —— 识别真正的可执行文件头：
   - PE (Windows)：`MZ` → 验证 `PE\0\0` 签名
   - ELF (Linux)：`\x7fELF`
   - Mach-O (macOS)：`FE ED FA CE` / `CE FA ED FE` 等
   - Fat/Universal binary：`CA FE BA BE` / `BE BA FE CA`
3. **脚本/文本检测** —— 识别 Perl 脚本、Shebang 脚本、纯文本文件：
   - Shebang 检查（`#!` 开头）
   - Perl 关键字检测（`use strict`、`use warnings`、`package ` 等）
   - UTF-8 可解码 + 90%+ 可打印字符

### 预过滤统计输出示例

```
============================================================
[PreFilter] 预过滤统计
============================================================
  扩展名过滤:       XXXXX
  大小不足 (<512B): XXXXX
  Magic bytes 放行: XXXXX  (PE/ELF/Mach-O)
  脚本/文本 过滤:    XXXXX
  未知格式 跳过:     XXXXX
  ───────────────────────────
  提交 IDA 处理:     XXXXX
```
