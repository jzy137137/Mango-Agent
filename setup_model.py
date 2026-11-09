"""Local setup window: user enters key; only encrypted bytes are stored."""
import threading
import tkinter as tk
from tkinter import ttk, messagebox

import agent
from credentials import save_key, load_key

def main():
    config_path = agent.ROOT / 'config.json'
    config = agent.read_json(config_path)
    root = tk.Tk()
    root.title('Mango Agent — DeepSeek 接口配置')
    root.geometry('640x400')
    panel = ttk.Frame(root, padding=20)
    panel.pack(fill='both', expand=True)
    base = tk.StringVar(value=config.get('llm_base_url') or 'https://api.deepseek.com')
    model = tk.StringVar(value=config.get('llm_model') or 'deepseek-flash')
    key = tk.StringVar()
    status = tk.StringVar(value='请输入你自己的 API Key；留空则使用已保存的密钥。')
    for label, value, hidden in [('API Base URL', base, False), ('模型名', model, False), ('API Key（隐藏输入）', key, True)]:
        ttk.Label(panel, text=label).pack(anchor='w', pady=(8, 2))
        ttk.Entry(panel, textvariable=value, show='*' if hidden else '', width=80).pack(fill='x')
    ttk.Label(panel, text='密钥使用当前 Windows 用户的 DPAPI 加密，保存在项目 secrets 目录。\n'
              '“保存并测试”只发送简单 JSON 连通性提示，不发送固件。', wraplength=590).pack(anchor='w', pady=12)
    ttk.Label(panel, textvariable=status, wraplength=590).pack(anchor='w')

    def submit():
        try:
            new_config = dict(config, llm_base_url=base.get().strip().rstrip('/'), llm_model=model.get().strip())
            if not new_config['llm_base_url'] or not new_config['llm_model']:
                raise ValueError('请填写接口地址和模型名')
            if key.get().strip():
                save_key(key.get())
                key.set('')
            if not load_key(new_config['api_key_env']):
                raise ValueError('请先输入 API Key')
            agent.save_json(config_path, new_config)
            config.update(new_config)
        except Exception as exc:
            messagebox.showerror('配置未完成', str(exc))
            return
        button.config(state='disabled')
        status.set('配置已保存，正在测试模型连接……')
        def worker():
            try:
                agent.test_model(new_config)
                message = '连接成功，可以关闭窗口，然后运行 start.cmd 菜单 4。'
                snapshot = {'status': 'connected', 'model': new_config['llm_model'], 'firmware_sent': False}
            except Exception as exc:
                message = '配置已保存，测试未通过：' + str(exc)
                snapshot = {'status': 'failed', 'error': str(exc), 'firmware_sent': False}
            agent.save_json(agent.ROOT / 'runs' / 'model-connection.json', snapshot)
            def done():
                status.set(message)
                button.config(state='normal')
            root.after(0, done)
        threading.Thread(target=worker, daemon=True).start()
    button = ttk.Button(panel, text='保存并测试连接', command=submit)
    button.pack(anchor='w', pady=12)
    root.mainloop()

if __name__ == '__main__':
    main()
