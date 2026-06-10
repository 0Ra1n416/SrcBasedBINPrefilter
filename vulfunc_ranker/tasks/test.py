import idapro
import ida_auto
import ida_idp
import ida_loader
import ida_pro
import ida_hexrays
import ida_lines
import ida_name
import os


"""测试PDB辅助反编译功能"""

def decompile_with_pdb(binary_path, pdb_path,output_dir):
    """
    加载二进制文件和PDB，并进行反编译
    """
    # 加载二进制文件
    print(f"Loading binary: {binary_path}")
    
    # 打开数据库并自动分析
    idapro.open_database(binary_path, True)

    
    # 等待自动分析完成
    ida_auto.auto_wait()
    
    # 如果有PDB文件，加载符号
    if pdb_path and os.path.exists(pdb_path):
        print(f"Loading PDB: {pdb_path}")
        #下面该句存在错误，需修改
        ida_loader.load_pdb(pdb_path)
        ida_auto.auto_wait()
    
    print("Starting decompilation...")

    # 反编译所有函数
    decompile_all_functions(output_dir)
    
    # 保存数据库
    output_idb = binary_path + ".i64"
    ida_loader.save_database(output_idb, ida_loader.DBFL_BAK)
    
    idapro.close_database()

    return output_idb

def decompile_all_functions(output_dir):
    """反编译所有可识别的函数"""
    for seg_ea in idautils.Segments():
        for func_ea in idautils.Functions(seg_ea, idc.get_segm_end(seg_ea)):
            try:
                decompile_function(func_ea, output_dir)
            except Exception as e:
                print(f"Failed to decompile function at {hex(func_ea)}: {e}")

def decompile_function(func_ea, output_dir):
    """反编译单个函数"""
    func_name = idc.get_func_name(func_ea)
    print(f"Decompiling function: {func_name} at {hex(func_ea)}")
    
    # 获取反编译对象
    cfunc = ida_hexrays.decompile(func_ea)
    if cfunc:
        # 获取伪代码
        pseudocode = str(cfunc)
        
        # 保存反编译结果到指定文件夹
        output_dir = "decompiled_functions"
        os.makedirs(output_dir, exist_ok=True)
        output_file = os.path.join(output_dir, f"decompiled_{func_name}.c")
        with open(output_file, "w") as f:
            f.write(f"// Function: {func_name}\n")
            f.write(f"// Address: {hex(func_ea)}\n\n")
            f.write(pseudocode)
        
        print(f"Saved decompilation to: {output_file}")

if __name__ == "__main__":
    
    import sys
    import idautils
    import idc
    
    binary_path = r"..\data\rumpusd.exe"
    pdb_path = r"..\data\rumpusd.pdb"
    output_dir = r"..\data\decompiled_functions"
    print(111111)
    print(binary_path)
    print(pdb_path)
    print(output_dir)
    decompile_with_pdb(binary_path, pdb_path,output_dir)
    idc.qexit(0)