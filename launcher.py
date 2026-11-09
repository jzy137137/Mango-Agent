import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
MENU = '''
Mango + IDA 候选路径审查 Agent
1. 检查环境与 IDA 连接
2. 列出已有 AC20 候选路径
3. 获取第 0 条路径的 IDA 证据（文件交接模式）
4. 自动运行第 0 条路径（需要配置模型 API）
5. 打开运行结果目录
6. 配置 DeepSeek 接口和密钥
0. 退出
'''
COMMANDS = {
    '1': ['agent.py', 'doctor'],
    '2': ['agent.py', 'list'],
    '3': ['agent.py', 'review', '--candidate', '0', '--mode', 'handoff'],
    '4': ['agent.py', 'review', '--candidate', '0', '--mode', 'api'],
    '6': ['setup_model.py'],
}

def main():
    os.chdir(ROOT)
    if not (ROOT / 'config.json').exists():
        shutil.copyfile(ROOT / 'config.example.json', ROOT / 'config.json')
    while True:
        print(MENU, flush=True)
        try:
            choice = input('请选择: ').strip()
        except (EOFError, KeyboardInterrupt):
            return
        if choice == '0':
            return
        if choice == '5':
            (ROOT / 'runs').mkdir(exist_ok=True)
            os.startfile(str(ROOT / 'runs'))
        elif choice in COMMANDS:
            subprocess.run([sys.executable, '-X', 'utf8', *COMMANDS[choice]], cwd=ROOT)
        else:
            print('请输入 0 到 6。')
            continue
        try:
            input('\n按回车返回菜单……')
        except (EOFError, KeyboardInterrupt):
            return

if __name__ == '__main__':
    main()