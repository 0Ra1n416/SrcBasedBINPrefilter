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
    '.idb', '.i64', '.idc', '.idap', '.idapro', '.idb.idc',
    # 其他数据文件
    '.vdb', '.bak', '.tmp', '.log'
})


def is_likely_binary(file_path: str) -> bool:
    """通过扩展名快速过滤明显不是二进制的文件。"""
    ext = os.path.splitext(file_path)[1].lower()
    return ext not in _NON_BINARY_EXTENSIONS

def pre_defined_source_funcs_count() -> int:
    """返回预定义的 Source 函数数量。"""
    return source_func_count()

def scan_folder(folder_path: str, 
                pre_defined_count: int, 
                use_absolute: bool = False, 
                timeout_per_file: int = 180) -> tuple[dict, dict, list]:
    """
    递归扫描文件夹中的所有二进制文件，统计每个文件的 Source 函数个数。

    :param folder_path: 要扫描的文件夹路径
    :param pre_defined_count: 预定义的 Source 函数数量
    :param use_absolute: 是否输出绝对路径，默认为 False（即相对路径）
    :param timeout_per_file: 每个二进制的超时时间（秒），超时则跳过；默认为 180 秒，设为 0 表示不限制
    """
    folder_path = os.path.abspath(folder_path)

    if not os.path.isdir(folder_path):
        print(f"Error: '{folder_path}' 不是一个有效的目录。")
        sys.exit(1)

    print(f"[PreFilter] 开始扫描文件夹: {folder_path}")
    if timeout_per_file > 0:
        print(f"[PreFilter] 单文件超时: {timeout_per_file} 秒")

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

    # 第二遍：用 tqdm 进度条逐个处理（每个二进制在子进程中运行，超时自动 kill）
    print("[PreFilter] 开始处理二进制文件...")
    results = {}   # file_path -> count (成功)
    timeouts = []    # file_path 列表 (超时)
    errors = {}    # file_path -> error_message

    p_bar = tqdm.tqdm(all_binaries, desc="处理二进制文件", unit="file")

    for file_path in p_bar:
        # 在进度条下方显示当前正在处理的二进制文件路径
        p_bar.set_postfix_str(os.path.relpath(file_path, folder_path))

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
            proc.join()  # 等待进程真正结束
            timeouts.append(file_path)
        else:
            # 子进程正常结束，读取结果
            try:
                status, fpath, data = result_queue.get_nowait()
                if status == 'ok':
                    results[fpath] = data
                else:
                    errors[fpath] = data
            except Exception:
                errors[file_path] = "子进程未返回结果"

    # 默认使用相对路径，除非指定了 --absolute
    if not use_absolute:
        results = {os.path.relpath(k, folder_path): v for k, v in results.items()}
        errors  = {os.path.relpath(k, folder_path): v for k, v in errors.items()}

    # 汇总
    print("\n" + "=" * 60)
    print("[OUT] 二进制文件处理汇总")
    print("=" * 60)

    print(f"跳过 (常见非二进制): {skipped}")
    print(f"成功处理:        {len(results)}")
    print(f"处理出错:        {len(errors)}")
    print(f"处理超时:        {len(timeouts)}")

    return results, errors, timeouts

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
    parser.add_argument("--timeout_output", type=str, default="timeouts.txt", help="超时文件列表输出路径（默认为 timeouts.txt）")
    parser.add_argument("--threshold", type=int, default=0, help="只输出 Source 函数数量超过该阈值的文件，默认为0（即输出所有文件）")
    parser.add_argument("-a", "--absolute", action="store_true", help="使用绝对路径输出（默认为相对路径）")
    parser.add_argument("-t", "--timeout", type=int, default=180, help="每个文件的超时秒数，超时则跳过；默认为 180 秒，设为 0 表示不限制")
    args = parser.parse_args()

    pre_defined_count = pre_defined_source_funcs_count()
    success, _, timeouts = scan_folder(args.folder_path, pre_defined_count, use_absolute=args.absolute, timeout_per_file=args.timeout)
    ranked_list = rank(success, args.threshold)
    store(ranked_list, timeouts, args.output, args.timeout_output)

if __name__ == "__main__":
    main()