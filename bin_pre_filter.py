"""
批量扫描：递归遍历指定文件夹中的所有二进制文件，
对每个文件调用 source_func_count_by_algorithm 计算 Source 函数个数。
排序分析: 最后输出每个文件的路径和对应的 Source 函数数量，按数量从高到低排序。
阈值过滤: 可以设置一个阈值，只输出 Source 函数数量超过该阈值的文件，方便快速定位潜在问题较多的二进制文件。

预过滤优化：
- Magic bytes 检测：识别 PE/ELF/Mach-O 可执行文件头
- Shebang/文本检测：过滤 Perl/Python/Shell 等脚本文件
- 文件大小阈值：跳过过小的文件

支持断点续跑（--resume）和按大小升序处理（--sort-by-size）。

Usage: python bin_pre_filter.py <folder_path>
"""

import sys
import os
import tqdm
import csv
import multiprocessing

# 将项目根目录加入 sys.path，以便导入 vulfunc_ranker 包
_CUR_DIR = os.path.dirname(os.path.abspath(__file__))
if _CUR_DIR not in sys.path:
    sys.path.insert(0, _CUR_DIR)

from vulfunc_ranker.vulfunc_rank import source_func_count_by_algorithm
from vulfunc_ranker.scripts.simple_source_count import source_func_count


def _process_binary_in_subprocess(binary_path: str, pre_defined_count: int, result_queue: multiprocessing.Queue) -> None:
    """
    在子进程中处理单个二进制文件。
    独立进程便于主进程施加超时控制——超时后可直接 kill。
    """
    import sys
    import os
    # 抑制 IDA/MCP 的 stdout 日志输出
    sys.stdout = open(os.devnull, 'w')
    try:
        count = source_func_count_by_algorithm(binary_path)
        result_queue.put(('ok', binary_path, count + pre_defined_count))
    except Exception as e:
        result_queue.put(('error', binary_path, str(e).strip()[:100]))


# 常见非二进制文件扩展名，扫描时跳过以提高效率
_NON_BINARY_EXTENSIONS = frozenset({
    # 脚本 / 源码
    '.py', '.pyc', '.pyo', '.pyw',
    '.txt', '.text', '.md', '.markdown', '.rst', '.readme',
    '.json', '.jsonc', '.xml', '.html', '.htm', '.xhtml',
    '.css', '.scss', '.sass', '.less',
    '.js', '.mjs', '.cjs', '.ts', '.jsx', '.tsx', '.vue', '.svelte',
    '.c', '.cpp', '.cc', '.cxx', '.h', '.hpp', '.hh', '.hxx',
    '.cs', '.java', '.kt', '.kts', '.scala', '.groovy',
    '.go', '.rs', '.rb', '.php', '.pl', '.pm',
    '.sh', '.bash', '.zsh', '.fish', '.ps1', '.psm1', '.psd1', '.bat', '.cmd',
    '.yaml', '.yml', '.toml', '.ini', '.cfg', '.conf', '.config',
    '.log', '.csv', '.tsv',
    '.tex', '.bib',
    '.gitignore', '.gitattributes', '.gitmodules', '.editorconfig', '.env',
    '.make', '.mk', '.cmake', '.gradle', '.sbt',
    '.sql',
    '.patch', '.diff',
    # 图片 / 音视频
    '.svg', '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico', '.webp',
    '.mp3', '.mp4', '.avi', '.mkv', '.wav', '.flac', '.ogg',
    # 文档 / 压缩包
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    '.zip', '.tar', '.gz', '.bz2', '.xz', '.7z', '.rar', '.cab',
    '.ipynb',
    # IDA数据文件
    '.idb', '.i64', '.idc', '.idap', '.idapro', '.idb.idc', '.id0', '.id1', '.id2', '.id3', '.nam', '.til', '.til64',
    # 其他数据文件
    '.vdb', '.bak', '.tmp'
})

# 额外的脚本文件扩展名（不在 _NON_BINARY_EXTENSIONS 中的）
_SCRIPT_EXTENSIONS = frozenset({
    '.cgi', '.psgi', '.fcgi',    # Perl/CGI 变体
    '.t', '.pod',                   # Perl 测试/文档
    '.lua', '.luac',
    '.r', '.R',
    '.swift',
    '.dart',
})


def is_likely_binary(file_path: str) -> bool:
    """通过扩展名快速过滤明显不是二进制的文件。"""
    ext = os.path.splitext(file_path)[1].lower()
    return ext not in _NON_BINARY_EXTENSIONS and ext not in _SCRIPT_EXTENSIONS


# ── Magic bytes / 文件头检测 ─────────────────────────────────────────────

# PE 文件签名
_MZ_SIGNATURE = b'MZ'
_PE_SIGNATURE = b'PE\x00\x00'

# ELF 文件签名
_ELF_SIGNATURE = b'\x7fELF'

# Mach-O 文件签名（4 种常见变体）
_MACHO_SIGNATURES = frozenset({
    b'\xfe\xed\xfa\xce',  # 32-bit big-endian
    b'\xfe\xed\xfa\xcf',  # 64-bit big-endian
    b'\xce\xfa\xed\xfe',  # 32-bit little-endian
    b'\xcf\xfa\xed\xfe',  # 64-bit little-endian
})

# Fat/Universal binary 签名
_FAT_SIGNATURES = frozenset({
    b'\xca\xfe\xba\xbe',
    b'\xbe\xba\xfe\xca',
})

# 常见脚本 shebang 前缀
_SHEBANG_PREFIX = b'#!'

# Perl 特征字符串（用于文本内容检测）
_PERL_MARKERS = [
    b'#!/usr/bin/perl',
    b'#!/usr/bin/env perl',
    b'#!/bin/perl',
    b'use strict',
    b'use warnings',
    b'use v5.',
    b'package ',
]

# 读取文件头的大小上限
_HEADER_READ_SIZE = 4096


def _read_file_header(file_path: str, size: int = _HEADER_READ_SIZE) -> bytes | None:
    """安全读取文件头若干字节。"""
    try:
        with open(file_path, 'rb') as f:
            return f.read(size)
    except (OSError, PermissionError):
        return None


def _is_mz_pe(header: bytes) -> bool:
    """
    检测 PE 文件：先检查 MZ 头，再验证 PE\0\0 签名。
    通过 0x3C 处的 DWORD 定位 PE signature。
    """
    if len(header) < 2 or header[:2] != _MZ_SIGNATURE:
        return False
    if len(header) < 0x40:
        return False
    # 读取 0x3C 处的 DWORD（PE signature offset，小端序）
    pe_offset = int.from_bytes(header[0x3C:0x40], 'little')
    if pe_offset + 4 > len(header):
        return False
    return header[pe_offset:pe_offset + 4] == _PE_SIGNATURE


def _is_elf(header: bytes) -> bool:
    """检测 ELF 文件。"""
    return len(header) >= 4 and header[:4] == _ELF_SIGNATURE


def _is_macho(header: bytes) -> bool:
    """检测 Mach-O 文件。"""
    return len(header) >= 4 and header[:4] in _MACHO_SIGNATURES


def _is_fat_binary(header: bytes) -> bool:
    """检测 Fat/Universal binary。"""
    return len(header) >= 4 and header[:4] in _FAT_SIGNATURES


def is_executable_binary(file_path: str) -> bool:
    """
    通过文件头 magic bytes 判断是否为可执行文件。
    支持 PE (Windows)、ELF (Linux)、Mach-O / Fat binary (macOS)。
    """
    header = _read_file_header(file_path, 1024)
    if header is None or len(header) < 4:
        return False
    return _is_mz_pe(header) or _is_elf(header) or _is_macho(header) or _is_fat_binary(header)


def _has_shebang(header: bytes) -> bool:
    """检查文件是否以 shebang (#!) 开头。"""
    return header[:2] == _SHEBANG_PREFIX


def _is_text_content(header: bytes) -> bool:
    """
    判断文件内容是否为文本：尝试 UTF-8 解码，计算可打印字符比例。
    返回 True 如果 >= 90% 的字节是可打印 ASCII 或合法 UTF-8 多字节序列。
    """
    if len(header) == 0:
        return True  # 空文件视为文本
    try:
        text = header.decode('utf-8')
        printable = sum(1 for c in text if c.isprintable() or c in '\n\r\t')
        return printable / max(len(text), 1) >= 0.90
    except UnicodeDecodeError:
        return False


def _has_perl_markers(header: bytes) -> bool:
    """检查文件内容是否包含 Perl 语言特征。"""
    for marker in _PERL_MARKERS:
        if marker in header:
            return True
    return False


def is_script_or_text(file_path: str) -> bool:
    """
    判断文件是否为脚本或纯文本文件。
    检查 shebang + 文本内容特征 + Perl 关键字。
    """
    header = _read_file_header(file_path)
    if header is None or len(header) == 0:
        return False  # 读取失败视为可疑，放行给 IDA 尝试

    # Shebang 检测
    if _has_shebang(header):
        return True

    # Perl 关键字检测（无 shebang 的情况）
    if _has_perl_markers(header):
        return True

    # 纯文本检测
    if _is_text_content(header):
        return True

    return False


def pre_defined_source_funcs_count() -> int:
    """返回预定义的 Source 函数数量。"""
    return source_func_count()


# ── Checkpoint 支持 ───────────────────────────────────────────────────────

def load_checkpoint(checkpoint_csv: str) -> tuple[dict[str, int], set[str]]:
    """读取已处理的文件路径集合。"""
    processed = {}
    processed_timeout = set()
    if not os.path.exists(checkpoint_csv):
        return processed, processed_timeout
    with open(checkpoint_csv, 'r', encoding='utf-8', newline='') as f:
        reader = csv.reader(f)
        for row in reader:
            if row:
                if row[1] == "timeout":
                    processed_timeout.add(row[0])
                else:
                    processed[row[0]] = int(row[1]) if row[1].isdigit() else 0
    return processed, processed_timeout


def append_checkpoint(checkpoint_csv: str, file_path: str, count: int, timeout: bool = False) -> None:
    """追加单条结果到 checkpoint。"""
    with open(checkpoint_csv, 'a', encoding='utf-8', newline='') as f:
        if timeout:
            csv.writer(f).writerow([file_path, "timeout"])
        else:
            csv.writer(f).writerow([file_path, count])


# ── 主扫描逻辑 ────────────────────────────────────────────────────────────

def scan_folder(folder_path: str,
                pre_defined_count: int,
                use_absolute: bool = False,
                timeout_per_file: int = 180,
                min_file_size: int = 512,
                sort_by_size: bool = True,
                strict: bool = True,
                dry_run: bool = False,
                checkpoint_csv: str | None = None) -> tuple[dict, dict, list]:
    """
    递归扫描文件夹中的所有二进制文件，统计每个文件的 Source 函数个数。

    :param folder_path: 要扫描的文件夹路径
    :param pre_defined_count: 预定义的 Source 函数数量
    :param use_absolute: 是否输出绝对路径，默认为 False（即相对路径）
    :param timeout_per_file: 每个二进制的超时时间（秒），超时则跳过；默认为 180 秒，设为 0 表示不限制
    :param min_file_size: 最小文件大小（字节），小于此值的文件跳过
    :param sort_by_size: 是否按文件大小升序处理（小文件优先，更快积攒进度）
    :param strict: 是否严格模式——跳过所有未识别格式（默认 True）
    :param dry_run: 仅统计过滤结果，不实际运行 IDA
    :param checkpoint_csv: Checkpoint CSV 路径，用于断点续跑
    """
    folder_path = os.path.abspath(folder_path)

    if not os.path.isdir(folder_path):
        print(f"Error: '{folder_path}' 不是一个有效的目录。")
        sys.exit(1)

    print(f"[PreFilter] 开始扫描文件夹: {folder_path}")
    if timeout_per_file > 0:
        print(f"[PreFilter] 单文件超时: {timeout_per_file} 秒")
    print(f"[PreFilter] 最小文件大小: {min_file_size} 字节")
    print(f"[PreFilter] 按大小升序: {'是' if sort_by_size else '否'}")
    print(f"[PreFilter] 严格模式: {'是' if strict else '否（放行未知格式）'}")

    # 加载 checkpoint
    checkpoint_processed = {}
    checkpoint_processed_timeout = set()
    if checkpoint_csv:
        checkpoint_processed, checkpoint_processed_timeout = load_checkpoint(checkpoint_csv)
        if checkpoint_processed or checkpoint_processed_timeout:
            print(f"[PreFilter] 从 checkpoint 恢复: 已处理 {len(checkpoint_processed) + len(checkpoint_processed_timeout)} 个文件")

    # ── 第一遍：收集所有候选文件，同时做预过滤统计 ──
    all_binaries = []
    stats = {
        "ext_skipped": 0,          # 扩展名过滤
        "size_skipped": 0,         # 大小不足
        "magic_passed": 0,         # magic bytes 识别为可执行
        "script_skipped": 0,       # shebang/文本/Perl 过滤
        "unknown_skipped": 0,      # 未知格式跳过
        "unknown_passed": 0,       # 未知格式放行（strict=False）
    }
    size_buckets_all = {"<1KB": 0, "1KB-10KB": 0, "10KB-100KB": 0,
                        "100KB-1MB": 0, "1MB-10MB": 0, "10MB-100MB": 0, ">100MB": 0}
    size_buckets_filtered = {"<1KB": 0, "1KB-10KB": 0, "10KB-100KB": 0,
                             "100KB-1MB": 0, "1MB-10MB": 0, "10MB-100MB": 0, ">100MB": 0}

    def _bucket(size: int) -> str:
        if size < 1024:
            return "<1KB"
        elif size < 10 * 1024:
            return "1KB-10KB"
        elif size < 100 * 1024:
            return "10KB-100KB"
        elif size < 1024 * 1024:
            return "100KB-1MB"
        elif size < 10 * 1024 * 1024:
            return "1MB-10MB"
        elif size < 100 * 1024 * 1024:
            return "10MB-100MB"
        else:
            return ">100MB"

    for root, dirs, files in os.walk(folder_path):
        for filename in files:
            file_path = os.path.join(root, filename)

            # Step 1: 扩展名过滤
            if not is_likely_binary(file_path):
                stats["ext_skipped"] += 1
                continue

            # 获取文件大小
            try:
                file_size = os.path.getsize(file_path)
            except OSError:
                continue

            size_buckets_all[_bucket(file_size)] += 1

            # Step 2: 大小阈值
            if file_size < min_file_size:
                stats["size_skipped"] += 1
                continue

            # Step 3: Magic bytes 检测
            is_exec = is_executable_binary(file_path)

            if is_exec:
                stats["magic_passed"] += 1
                size_buckets_filtered[_bucket(file_size)] += 1
                all_binaries.append(file_path)
            else:
                # Step 4: Shebang / 文本 / Perl 检测
                is_script = is_script_or_text(file_path)
                if is_script:
                    stats["script_skipped"] += 1
                elif strict:
                    stats["unknown_skipped"] += 1
                else:
                    stats["unknown_passed"] += 1
                    size_buckets_filtered[_bucket(file_size)] += 1
                    all_binaries.append(file_path)

    # ── 打印预过滤统计 ──
    print("\n" + "=" * 60)
    print("[PreFilter] 预过滤统计")
    print("=" * 60)
    print(f"  扩展名过滤:      {stats['ext_skipped']:>6}")
    print(f"  大小不足 (<{min_file_size}B): {stats['size_skipped']:>6}")
    print(f"  Magic bytes 放行:{stats['magic_passed']:>6}  (PE/ELF/Mach-O)")
    print(f"  脚本/文本 过滤:   {stats['script_skipped']:>6}")
    if strict:
        print(f"  未知格式 跳过:    {stats['unknown_skipped']:>6}")
    else:
        print(f"  未知格式 放行:    {stats['unknown_passed']:>6}")
    total_filtered = sum(v for k, v in stats.items() if k.endswith('_passed'))
    print(f"  ───────────────────────────")
    print(f"  提交 IDA 处理:    {total_filtered:>6}")

    print("\n[PreFilter] 全量文件大小分布:")
    for bucket in ["<1KB", "1KB-10KB", "10KB-100KB", "100KB-1MB", "1MB-10MB", "10MB-100MB", ">100MB"]:
        print(f"  {bucket}: {size_buckets_all[bucket]}")

    print("\n[PreFilter] 过滤后（提交 IDA）文件大小分布:")
    for bucket in ["<1KB", "1KB-10KB", "10KB-100KB", "100KB-1MB", "1MB-10MB", "10MB-100MB", ">100MB"]:
        print(f"  {bucket}: {size_buckets_filtered[bucket]}")

    if dry_run:
        print("\n[PreFilter] --dry-run 模式：仅统计，不执行 IDA 分析。")
        return {}, {}, []

    # ── 按大小排序（小文件优先） ──
    if sort_by_size:
        all_binaries.sort(key=lambda p: os.path.getsize(p) if os.path.exists(p) else 0)

    # ── 第二遍：用 tqdm 进度条逐个处理 ──
    print(f"\n[PreFilter] 开始处理 {len(all_binaries)} 个二进制文件...")
    results = {}     # file_path -> count (成功)
    timeouts = []    # file_path 列表 (超时)
    errors = {}      # file_path -> error_message

    if checkpoint_processed:
        for p, cnt in checkpoint_processed.items():
            results[p] = cnt
    if checkpoint_processed_timeout:
        for p in checkpoint_processed_timeout:
            timeouts.append(p)

    # 去掉已 checkpoint 处理过的文件
    if checkpoint_processed or checkpoint_processed_timeout:
        before = len(all_binaries)
        skip_set = set(checkpoint_processed.keys()) | checkpoint_processed_timeout
        all_binaries = [p for p in all_binaries if p not in skip_set]
        if before != len(all_binaries):
            print(f"[PreFilter] Checkpoint 跳过已处理: {before - len(all_binaries)} 个")

    if not all_binaries:
        print("[PreFilter] 没有需要处理的文件。")
        return results, errors, timeouts

    p_bar = tqdm.tqdm(all_binaries, desc="处理二进制文件", unit="file",
                      smoothing=0.01)  # 低平滑系数，ETA 更灵敏

    for file_path in p_bar:
        rel_path = os.path.relpath(file_path, folder_path)
        # 在进度条下方显示当前文件
        p_bar.set_postfix_str(rel_path[:60])

        result_queue: multiprocessing.Queue = multiprocessing.Queue()
        proc = multiprocessing.Process(
            target=_process_binary_in_subprocess,
            args=(file_path, pre_defined_count, result_queue),
            daemon=True,
        )
        proc.start()
        proc.join(timeout=timeout_per_file if timeout_per_file > 0 else None)

        if proc.is_alive():
            # 超时：强制终止子进程
            proc.kill()
            proc.join()
            timeouts.append(file_path)
            if checkpoint_csv:
                append_checkpoint(checkpoint_csv, file_path, 0, timeout=True)
        else:
            try:
                status, fpath, data = result_queue.get_nowait()
                if status == 'ok':
                    results[fpath] = data
                    # 立即写入 checkpoint
                    if checkpoint_csv:
                        append_checkpoint(checkpoint_csv, fpath, data)
                else:
                    errors[fpath] = data
            except Exception:
                errors[file_path] = "子进程未返回结果"

    # 默认使用相对路径，除非指定了 --absolute
    if not use_absolute:
        results = {os.path.relpath(k, folder_path): v for k, v in results.items()}
        errors = {os.path.relpath(k, folder_path): v for k, v in errors.items()}
        timeouts = [os.path.relpath(p, folder_path) for p in timeouts]

    # 汇总
    print("\n" + "=" * 60)
    print("[OUT] 二进制文件处理汇总")
    print("=" * 60)

    print(f"预过滤跳过:       {sum(v for k, v in stats.items() if k.endswith('_skipped'))}")
    print(f"成功处理:         {len(results)}")
    print(f"处理出错:         {len(errors)}")
    print(f"处理超时:         {len(timeouts)}")

    return results, errors, timeouts


def rank(success: dict, threshold: int = 0) -> list[tuple[str, int]]:
    """
    对成功处理的结果进行排序，并根据阈值过滤。

    :param success: 成功处理的结果，格式为 {file_path: count}
    :param threshold: 只输出 Source 函数数量超过该阈值的文件，默认为0（即输出所有文件）

    :return ranked_list: 排序后的列表，格式为 [(file_path, count), ...]
    """
    message = f"\n[PreFilter] 开始排序..."
    if threshold > 0:
        message = f"\n[PreFilter] 开始排序与过滤 (阈值: {threshold})..."
    print(message)

    filtered = [(fp, cnt) for fp, cnt in success.items() if cnt >= threshold]
    ranked_list = sorted(filtered, key=lambda x: x[1], reverse=True)

    return ranked_list


def store(ranked_list: list[tuple[str, int]], timeouts: list[str], output_path: str, timeout_output_path: str) -> None:
    """
    将排序后的结果存储到 CSV 文件中。

    :param ranked_list: 排序后的列表，格式为 [(file_path, count), ...]
    :param timeouts: 超时文件列表
    :param output_path: 输出 CSV 文件路径
    :param timeout_output_path: 超时文件列表输出路径
    """
    with open(output_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["file_path", "source_count"])
        for file_path, count in ranked_list:
            writer.writerow([file_path, count])
    with open(timeout_output_path, "w", encoding="utf-8") as f:
        for file_path in timeouts:
            f.write(f"{file_path}\n")
    print(f"[PreFilter] 结果已保存到: {output_path} 和 {timeout_output_path}")


def main():
    import argparse
    parser = argparse.ArgumentParser(description="批量扫描文件夹中的二进制文件，统计每个文件的 Source 函数数量。")
    parser.add_argument("folder_path", help="要扫描的文件夹路径")
    parser.add_argument("--output", type=str, default="output.csv", help="输出 CSV 文件路径（默认为 output.csv）")
    parser.add_argument("--timeout-output", type=str, default="timeouts.txt", help="超时文件列表输出路径（默认为 timeouts.txt）")
    parser.add_argument("--threshold", type=int, default=0, help="只输出 Source 函数数量超过该阈值的文件，默认为0（即输出所有文件）")
    parser.add_argument("-a", "--absolute", action="store_true", help="使用绝对路径输出（默认为相对路径）")
    parser.add_argument("-t", "--timeout", type=int, default=180, help="每个文件的超时秒数，超时则跳过；默认为 180 秒，设为 0 表示不限制")
    parser.add_argument("--min-size", type=int, default=512, help="最小文件大小（字节），小于此值的文件跳过；默认 512")
    parser.add_argument("--no-sort", action="store_true", help="不按文件大小升序排列（默认会按大小升序）")
    parser.add_argument("--no-strict", action="store_true", help="非严格模式：放行所有未识别格式（默认严格模式，跳过未识别）")
    parser.add_argument("--dry-run", action="store_true", help="仅统计过滤结果，不实际运行 IDA")
    parser.add_argument("--resume", type=str, default=None, help="断点续跑：指定 checkpoint CSV 路径")
    parser.add_argument("--checkpoint", type=str, default=None, help="Checkpoint CSV 路径（默认与 --resume 相同）")
    args = parser.parse_args()

    strict_mode = not args.no_strict  # 默认严格模式，--no-strict 关闭

    pre_defined_count = pre_defined_source_funcs_count()
    checkpoint_csv = args.checkpoint or args.resume

    success, errors, timeouts = scan_folder(
        args.folder_path,
        pre_defined_count,
        use_absolute=args.absolute,
        timeout_per_file=args.timeout,
        min_file_size=args.min_size,
        sort_by_size=not args.no_sort,
        strict=strict_mode,
        dry_run=args.dry_run,
        checkpoint_csv=checkpoint_csv,
    )

    if args.dry_run:
        return

    ranked_list = rank(success, args.threshold)
    store(ranked_list, timeouts, args.output, args.timeout_output)


if __name__ == "__main__":
    main()
