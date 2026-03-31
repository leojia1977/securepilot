"""
deploy/setup.py — SecuPilot 一键部署脚本

客户运行此脚本完成环境检查、依赖安装和服务验证。
"""

import os
import shutil
import subprocess
import sys


def _check_cmd(cmd: list[str], min_version: tuple[int, ...] | None = None) -> bool:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return result.returncode == 0
    except Exception:
        return False


def step1_check_env() -> None:
    print("── 步骤1：环境检查 ──────────────────────────────")

    # Python 版本
    v = sys.version_info
    if v < (3, 11):
        print(f"  ✗ Python 版本不满足：需要 3.11+，当前 {v.major}.{v.minor}")
        sys.exit(1)
    print(f"  ✓ Python {v.major}.{v.minor}.{v.micro}")

    # Docker
    if not _check_cmd(["docker", "--version"]):
        print("  ✗ docker 未安装或不可用")
        sys.exit(1)
    print("  ✓ docker 可用")

    # Docker Compose
    if not _check_cmd(["docker", "compose", "version"]):
        print("  ✗ docker compose 未安装或不可用")
        sys.exit(1)
    print("  ✓ docker compose 可用")


def step2_create_env() -> None:
    print("── 步骤2：创建 .env 文件 ────────────────────────")
    env_path = ".env"
    example_path = ".env.example"

    if os.path.exists(env_path):
        print("  .env 已存在，跳过")
        return

    if os.path.exists(example_path):
        shutil.copy(example_path, env_path)
        print(f"  ✓ 已从 {example_path} 复制创建 .env")
    else:
        print("  ⚠ .env.example 不存在，请手动创建 .env")


def step3_create_data_dir() -> None:
    print("── 步骤3：创建数据目录 ──────────────────────────")
    os.makedirs("data", exist_ok=True)
    print("  ✓ data/ 目录就绪")


def step4_install_deps() -> None:
    print("── 步骤4：安装 Python 依赖 ──────────────────────")
    result = subprocess.run(
        [sys.executable, "-m", "pip", "install", "-r", "requirements.txt", "-q"],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        print("  ✗ 依赖安装失败：")
        print(result.stderr[:500])
        sys.exit(1)
    print("  ✓ 依赖安装完成")


def step5_choose_mode() -> str:
    print("── 步骤5：选择部署模式 ──────────────────────────")
    print("  请选择部署模式：")
    print("  [1] Mock 模式（无需 GPU，用于演示）")
    print("  [2] 生产模式（需要已部署的 vLLM 服务）")
    choice = input("  请输入 1 或 2：").strip()
    if choice == "1":
        os.environ["KAFKA_MOCK"] = "true"
        print("  ✓ 已选择 Mock 模式")
        return "mock"
    else:
        os.environ["KAFKA_MOCK"] = "false"
        print("  ✓ 已选择生产模式")
        return "prod"


def step6_verify(mode: str) -> None:
    print("── 步骤6：启动服务验证 ──────────────────────────")
    if mode == "mock":
        result = subprocess.run(
            [sys.executable, "tests/sprint0_acceptance.py"],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            print("  ✗ 环境验证失败：")
            print(result.stdout[-500:])
            print(result.stderr[-200:])
            sys.exit(1)
        print("  ✓ 环境验证通过，系统就绪")
    else:
        print("  生产模式跳过自动验证，请手动验证服务")


def step7_print_info() -> None:
    print()
    print("==========================================")
    print("SecuPilot 部署完成")
    print("Dashboard: http://localhost:8080")
    print("API 文档:  http://localhost:8080/docs")
    print("健康检查: http://localhost:8080/health")
    print("==========================================")


if __name__ == "__main__":
    step1_check_env()
    step2_create_env()
    step3_create_data_dir()
    step4_install_deps()
    mode = step5_choose_mode()
    step6_verify(mode)
    step7_print_info()
