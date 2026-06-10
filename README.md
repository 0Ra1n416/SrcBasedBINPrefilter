# SrcBasedBINPrefilter

批量预过滤工具 —— 递归扫描文件夹中的二进制文件，对每个文件通过 IDA Pro 反编译 + 启发式分析，计算出 **Source 函数**的数量，最终按数量排序输出 CSV，用于快速筛选潜在攻击面较大的二进制文件。

## 目录

- [环境依赖](#环境依赖)
- [快速开始](#快速开始)
- [命令行参数](#命令行参数)

## 环境依赖

- **Python** ≥ 3.10
- **IDA Pro**，请配置好环境变量`IDADIR`(Windows)，其他平台请自行查阅
- **ida-pro-mcp**
- Python 包（见 `vulfunc_ranker/requirement.txt`）：

```bash
pip install -r vulfunc_ranker/requirement.txt
```

## 快速开始

使用示例：

```bash
python bin_pre_filter.py <folder_path>
```

```bash
python bin_pre_filter.py C:\samples\ --output result.csv --threshold 5
```

```bash
# 输出绝对路径（默认相对路径）
python bin_pre_filter.py C:\samples\ -a
```

## 命令行参数

### `bin_pre_filter.py`

| 参数 | 说明 | 默认值 |
| ------ | ------ | -------- |
| `folder_path` | 要扫描的文件夹路径（必填） | — |
| `--output` | 输出 CSV 文件路径 | `output.csv` |
| `--threshold` | 只输出 Source 函数数量超过该阈值的文件 | `0`（输出所有） |
| `-a`, `--absolute` | 使用绝对路径输出 | 关闭（默认相对路径） |
