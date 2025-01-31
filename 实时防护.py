import os
import hashlib
import psutil
import subprocess
import tkinter as tk
from tkinter import messagebox
import time
import threading
from queue import PriorityQueue

# 自定义类用于包含优先级和 Process 对象
class PrioritizedProcess:
    def __init__(self, priority, process):
        self.priority = priority
        self.process = process

    def __lt__(self, other):
        return self.priority < other.priority

# 读取 MD5 库
def load_md5_library(md5_lib_path):
    with open(md5_lib_path, 'r') as f:
        md5_list = f.read().splitlines()
    return md5_list

# 计算文件的 MD5
def calculate_md5(file_path):
    if not os.path.isfile(file_path):
        return None
    hash_md5 = hashlib.md5()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

# 调用 APEX 扫描文件
def scan_with_apex(file_path, apex_path, current_path):
    # 排除自身进程
    if file_path == current_path:
        return False
    result = subprocess.run([apex_path, '/s=1', f'/f={file_path}'], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
    return 'Malicious' in result.stdout

# 弹窗询问用户是否结束进程
def ask_user_to_terminate(process_name, process_path):
    root = tk.Tk()
    root.withdraw()  # 隐藏主窗口
    msg = f"检测到危险程序，是否结束进程\n\n进程名称：{process_name}\n进程目录：{process_path}"
    result = messagebox.askyesno("危险程序检测", msg)
    root.destroy()
    return result

# 处理进程检测
def handle_process(proc, md5_list, apex_path, lock, alert_lock, current_path):
    try:
        process_name = proc.info['name']
        process_path = proc.info['exe']

        if process_path is None or not os.path.isfile(process_path):
            return

        # 检查是否是当前脚本
        if process_path == current_path:
            return

        md5_value = calculate_md5(process_path)
        md5_match = md5_value and md5_value in md5_list

        # MD5 检测
        if md5_match:
            with alert_lock:
                proc.suspend()
                if ask_user_to_terminate(process_name, process_path):
                    proc.terminate()
                else:
                    proc.resume()
            return

        # APEX 检测
        if scan_with_apex(process_path, apex_path, current_path):
            with alert_lock:
                proc.suspend()
                if ask_user_to_terminate(process_name, process_path):
                    proc.terminate()
                else:
                    proc.resume()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        pass

# 线程工作函数
def worker(md5_list, apex_path, lock, alert_lock, queue, current_path):
    while True:
        prioritized_proc = queue.get()
        if prioritized_proc is None:
            break
        handle_process(prioritized_proc.process, md5_list, apex_path, lock, alert_lock, current_path)
        queue.task_done()

# 检测并处理进程
def check_and_process_procs(md5_list, apex_path, lock, alert_lock, queue, current_pid, checked_processes, current_path):
    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        if proc.pid == current_pid:
            continue
        priority = 1 if not proc.info['exe'] or not proc.info['exe'].startswith('C:\\Windows') else 10
        if proc.pid not in checked_processes:
            # 新进程优先级提高
            queue.put(PrioritizedProcess(priority - 1, proc))
        else:
            queue.put(PrioritizedProcess(priority, proc))
        checked_processes[proc.pid] = proc.info['exe']

# 主程序逻辑
def main():
    md5_lib_path = 'bd/bdk.vrb'
    apex_path = 'bd/apex/apexscan.exe'
    md5_list = load_md5_library(md5_lib_path)
    current_pid = os.getpid()
    current_path = os.path.realpath(__file__)  # 获取当前脚本的绝对路径
    checked_processes = {}
    lock = threading.Lock()
    alert_lock = threading.Lock()  # 用于控制弹窗
    queue = PriorityQueue()

    # 启动工作线程
    num_worker_threads = 10
    threads = []
    for _ in range(num_worker_threads):
        t = threading.Thread(target=worker, args=(md5_list, apex_path, lock, alert_lock, queue, current_path))
        t.start()
        threads.append(t)

    while True:
        check_and_process_procs(md5_list, apex_path, lock, alert_lock, queue, current_pid, checked_processes, current_path)
        time.sleep(1)

    # 等待队列清空
    queue.join()

    # 停止工作线程
    for _ in range(num_worker_threads):
        queue.put(None)
    for t in threads:
        t.join()

if __name__ == "__main__":
    main()
