import ast
import re
import os
import sys

def main():
    file_path = "tests/sprint0_acceptance.py"
    
    if not os.path.exists(file_path):
        print(f"❌ 找不到文件：{file_path}")
        sys.exit(1)

    try:
        with open(file_path, encoding='utf-8') as f:
            src = f.read()
    except:
        print("❌ 读取文件失败")
        sys.exit(1)

    # 1. 语法检查
    try:
        ast.parse(src)
        print("[1] 语法检查: OK")
    except:
        print("[1] 语法错误: FAIL")
        return

    # 2. 环境变量
    if '_load_dotenv' in src or 'load_dotenv' in src and 'os.environ.get' in src:
        print("[2] 从 .env 读取配置 (不硬编码): OK")
    else:
        print("[2] 未正确使用环境变量: FAIL")

    # 3. 6个检测函数
    required_funcs = [
        'check_vllm_health', 'check_vllm_inference',
        'check_postgres', 'check_qdrant',
        'check_kafka', 'check_synthetic_alerts'
    ]
    ok = all(fn in src for fn in required_funcs)
    if ok:
        print("[3] 6 个检测项函数: OK")
    else:
        print("[3] 缺少检测函数: FAIL")

    # 4. 输出关键字
    if 'Sprint 0 验收报告' in src and 'Sprint 0 门禁解锁' in src and 'sys.exit(1)' in src:
        print("[4] 输出格式关键字: OK")
    else:
        print("[4] 缺少输出关键字: FAIL")

    # 5. import 检查
    allowed = {'json','os','re','sys','pathlib','asyncio','httpx','asyncpg','kafka','dotenv'}
    imports = re.findall(r'^(?:import|from)\s+(\w+)', src, re.MULTILINE)
    valid = all(pkg in allowed for pkg in imports)
    if valid:
        print("[5] import 范围检查: OK")
    else:
        print("[5] 存在非允许的 import: FAIL")

    print("\n✅ 脚本执行完成")

if __name__ == "__main__":
    main()