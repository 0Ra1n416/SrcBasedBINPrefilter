"""
批量扫描：递归遍历指定文件夹中的所有二进制文件，
对每个文件调用 source_func_count_by_algorithm 计算 Source 函数个数。
排序分析: 最后输出每个文件的路径和对应的 Source 函数数量，按数量从高到低排序。
阈值过滤: 可以设置一个阈值，只输出 Source 函数数量超过该阈值的文件，方便快速定位潜在问题较多的二进制文件。

Usage: python bin_pre_filter.py <folder_path>
"""

import sys
import os
import tqdm
import csv
from contextlib import contextmanager

# 将项目根目录加入 sys.path，以便导入 vulfunc_ranker 包
_CUR_DIR = os.path.dirname(os.path.abspath(__file__))
if _CUR_DIR not in sys.path:
    sys.path.insert(0, _CUR_DIR)

from vulfunc_ranker.vulfunc_rank import source_func_count_by_algorithm


@contextmanager
def suppress_stdout():
    """临时抑制 stdout，用于屏蔽 ida-pro-mcp 插件的日志输出。"""
    devnull = open(os.devnull, 'w')
    old_stdout = sys.stdout
    sys.stdout = devnull
    try:
        yield
    finally:
        sys.stdout = old_stdout
        devnull.close()


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
    '.idb', '.i64', '.idc', '.idap', '.idapro', '.idb.idc',
})


def is_likely_binary(file_path: str) -> bool:
    """通过扩展名快速过滤明显不是二进制的文件。"""
    ext = os.path.splitext(file_path)[1].lower()
    return ext not in _NON_BINARY_EXTENSIONS


def scan_folder(folder_path: str, use_absolute: bool = False) -> tuple[dict, dict]:
    """
    递归扫描文件夹中的所有二进制文件，统计每个文件的 Source 函数个数。

    :param folder_path: 要扫描的文件夹路径
    :param use_absolute: 是否输出绝对路径，默认为 False（即相对路径）
    """
    folder_path = os.path.abspath(folder_path)

    if not os.path.isdir(folder_path):
        print(f"Error: '{folder_path}' 不是一个有效的目录。")
        sys.exit(1)

    print(f"[PreFilter] 开始扫描文件夹: {folder_path}")

    # 第一遍：收集所有待处理的二进制文件
    all_binaries = []
    skipped = 0

    for root, dirs, files in os.walk(folder_path):
        for filename in files:
            file_path = os.path.join(root, filename)
            if is_likely_binary(file_path):
                all_binaries.append(file_path)
            else:
                skipped += 1

    print(f"[OUT] 共发现 {len(all_binaries)} 个二进制文件，跳过 {skipped} 个常见非二进制文件")

    # 第二遍：用 tqdm 进度条逐个处理
    print("[PreFilter] 开始处理二进制文件...")
    results = {}   # file_path -> count (成功)
    errors = {}    # file_path -> error_message

    for file_path in tqdm.tqdm(all_binaries, desc="处理二进制文件", unit="file"):
        try:
            with suppress_stdout():
                count = source_func_count_by_algorithm(file_path)
            results[file_path] = count
        except Exception as e:
            errors[file_path] = str(e).strip()[:100]  # 记录错误信息，限制长度避免过长
            tqdm.tqdm.write(f"[ERROR] {file_path} -> {type(e).__name__}: {e}")

    # 默认使用相对路径，除非指定了 --absolute
    if not use_absolute:
        results = {os.path.relpath(k, folder_path): v for k, v in results.items()}
        errors  = {os.path.relpath(k, folder_path): v for k, v in errors.items()}

    # 汇总
    print("\n" + "=" * 60)
    print("[OUT] 二进制文件处理汇总")
    print("=" * 60)

    success = {k: v for k, v in results.items() if v is not None}
    errors  = {k: v for k, v in results.items() if v is None}

    print(f"跳过 (常见非二进制): {skipped}")
    print(f"成功处理:        {len(success)}")
    print(f"处理出错:        {len(errors)}")

    return success, errors

def rank(success: dict, threshold: int = 0) -> list[tuple[str, int]]:
    """
    对成功处理的结果进行排序，并根据阈值过滤。

    :param success: 成功处理的结果，格式为 {file_path: count}
    :param threshold: 只输出 Source 函数数量超过该阈值的文件，默认为0（即输出所有文件）

    :return ranked_list: 排序后的列表，格式为 [(file_path, count), ...]
    """
    # 过滤并排序
    message = f"\n[PreFilter] 开始排序..."
    if threshold > 0:
        message = f"\n[PreFilter] 开始排序与过滤 (阈值: {threshold})..."
    print(message)
    
    filtered = [(fp, cnt) for fp, cnt in success.items() if cnt >= threshold]
    ranked_list = sorted(filtered, key=lambda x: x[1], reverse=True)

    return ranked_list

def store(ranked_list: list[tuple[str, int]], output_path: str) -> None:
    """
    将排序后的结果存储到 CSV 文件中。

    :param ranked_list: 排序后的列表，格式为 [(file_path, count), ...]
    :param output_path: 输出 CSV 文件路径
    """
    with open(output_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["file_path", "source_count"])
        for file_path, count in ranked_list:
            writer.writerow([file_path, count])
    print(f"[PreFilter] 结果已保存到: {output_path}")

def main():
    import argparse
    parser = argparse.ArgumentParser(description="批量扫描文件夹中的二进制文件，统计每个文件的 Source 函数数量。")
    parser.add_argument("folder_path", help="要扫描的文件夹路径")
    parser.add_argument("--output", type=str, default="output.csv", help="输出 CSV 文件路径（默认为 output.csv）")
    parser.add_argument("--threshold", type=int, default=0, help="只输出 Source 函数数量超过该阈值的文件，默认为0（即输出所有文件）")
    parser.add_argument("-a", "--absolute", action="store_true", help="使用绝对路径输出（默认为相对路径）")
    args = parser.parse_args()

    success, _ = scan_folder(args.folder_path, use_absolute=args.absolute)
    ranked_list = rank(success, args.threshold)
    store(ranked_list, args.output)

if __name__ == "__main__":
    main()