import os
import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
import subprocess
import requests
import threading
import tempfile
import zipfile
from datetime import datetime, timedelta

class VirusScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("枫诗病毒检测工具 V2.2")
        self.root.geometry("900x750")  # 调整窗口大小

        self.logged_entries = {}  # 用于跟踪已记录的条目，键为文件路径
        self.create_widgets()

        self.update_thread = None  # 用于跟踪更新线程
        self.stop_update = threading.Event()  # 停止更新的事件

        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)  # 处理窗口关闭事件

    def create_widgets(self):
        self.font = ("SimSun", 12)

        self.dir_label = tk.Label(self.root, text="等待扫描的目录:", font=self.font)
        self.dir_label.pack(pady=10)

        self.dir_entry = tk.Entry(self.root, width=70, font=self.font)
        self.dir_entry.pack(pady=10)

        self.select_dir_button = tk.Button(self.root, text="选择目录", command=self.select_directory, font=self.font)
        self.select_dir_button.pack(pady=10)

        self.scan_button = tk.Button(self.root, text="开始扫描", command=self.start_scan_thread, font=self.font)
        self.scan_button.pack(pady=10)

        self.log_text = scrolledtext.ScrolledText(self.root, width=100, height=25, font=self.font, state=tk.DISABLED)
        self.log_text.pack(pady=20)

        self.bottom_frame = tk.Frame(self.root)
        self.bottom_frame.pack(pady=10)

        self.about_button = tk.Button(self.bottom_frame, text="关于", command=self.show_about, font=self.font)
        self.about_button.pack(side=tk.LEFT, padx=10)

        self.save_log_button = tk.Button(self.bottom_frame, text="写出日志", command=self.save_log, font=self.font)
        self.save_log_button.pack(side=tk.LEFT, padx=10)

        self.update_button = tk.Button(self.bottom_frame, text="检测更新", command=self.confirm_update, font=self.font)
        self.update_button.pack(side=tk.LEFT, padx=10)

        self.db_tool_button = tk.Button(self.bottom_frame, text="病毒入库工具", command=self.open_db_tool, font=self.font)
        self.db_tool_button.pack(side=tk.LEFT, padx=10)

        self.hug_button = tk.Button(self.bottom_frame, text="抱抱", command=self.hug, font=self.font)
        self.hug_button.pack(side=tk.LEFT, padx=10)

        self.progress_label = tk.Label(self.root, text="", font=self.font)
        self.progress_label.pack(pady=10)

        self.progress_frame = tk.Frame(self.root)
        self.progress_frame.pack(pady=10)

        # T3 进度条
        self.progress_label_t3 = tk.Label(self.progress_frame, text="T3:", font=self.font)
        self.progress_label_t3.pack(side=tk.LEFT, padx=10)

        self.progress_bar_t3 = ttk.Progressbar(self.progress_frame, orient="horizontal", length=200, mode="determinate")
        self.progress_bar_t3.pack(side=tk.LEFT, padx=10)

        self.progress_percentage_t3 = tk.Label(self.progress_frame, text="0%", font=self.font)
        self.progress_percentage_t3.pack(side=tk.LEFT, padx=10)

        # APEX 进度条
        self.progress_label_apex = tk.Label(self.progress_frame, text="APEX:", font=self.font)
        self.progress_label_apex.pack(side=tk.LEFT, padx=10)

        self.progress_bar_apex = ttk.Progressbar(self.progress_frame, orient="horizontal", length=200, mode="determinate")
        self.progress_bar_apex.pack(side=tk.LEFT, padx=10)

        self.progress_percentage_apex = tk.Label(self.progress_frame, text="0%", font=self.font)
        self.progress_percentage_apex.pack(side=tk.LEFT, padx=10)

        # 初始时隐藏进度条和百分比标签
        self.hide_progress()

    def select_directory(self):
        self.dir_entry.delete(0, tk.END)
        directory = filedialog.askdirectory()
        if directory:
            self.dir_entry.insert(0, directory)

    def start_scan_thread(self):
        scan_thread = threading.Thread(target=self.start_scan)
        scan_thread.start()

    def start_scan(self):
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete(1.0, tk.END)
        self.logged_entries.clear()  # 清空已记录条目，进行新的扫描

        directory = self.dir_entry.get()
        if not directory:
            messagebox.showwarning("警告", "请选择一个目录")
            return

        start_time = datetime.now()
        self.log_text.insert(tk.END, f"开始扫描目录: {directory} - {start_time.strftime('%Y-%m-%d %H:%M:%S')}\n")

        virus_count = 0

        for root, _, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                md5_hash = self.calculate_md5(file_path)

                if self.is_in_whitelist(md5_hash):
                    continue

                is_virus = False
                if os.path.exists("bd\\bdk.vrb") and self.is_in_virus_db(md5_hash):
                    log_entry = r"{} 病毒名称：Malware.Gen 查杀引擎：本地查杀".format(file_path.replace('/', '\\'))
                    if file_path not in self.logged_entries:
                        self.log_text.insert(tk.END, f"{log_entry}\n")
                        self.logged_entries[file_path] = "Malware.Gen"
                        virus_count += 1
                        is_virus = True

                if not is_virus:
                    result_apex = self.scan_with_apex(file_path)
                    if "Malicious" in result_apex:
                        log_entry = r"{} 病毒名称：Malicious 查杀引擎：APEX".format(file_path.replace('/', '\\'))
                        if file_path not in self.logged_entries:
                            self.log_text.insert(tk.END, f"{log_entry}\n")
                            self.logged_entries[file_path] = "Malicious"
                            virus_count += 1

                    result_t3 = self.scan_with_t3(file_path)
                    if result_t3:
                        log_entry = r"{} 病毒名称：{} 查杀引擎：T3".format(file_path.replace('/', '\\'), result_t3)
                        if file_path not in self.logged_entries:
                            self.log_text.insert(tk.END, f"{log_entry}\n")
                            self.logged_entries[file_path] = result_t3
                            virus_count += 1

        end_time = datetime.now()
        duration = end_time - start_time
        self.log_text.insert(tk.END, f"扫描完成，并且发现病毒：{virus_count}个\n")
        if duration < timedelta(minutes=1):
            self.log_text.insert(tk.END, f"扫描时间：{duration.seconds}秒\n")
        else:
            minutes, seconds = divmod(duration.seconds, 60)
            self.log_text.insert(tk.END, f"扫描时间：{minutes}分钟{seconds}秒\n")
        self.log_text.config(state=tk.DISABLED)

    def calculate_md5(self, file_path):
        hasher = hashlib.md5()
        with open(file_path, 'rb') as f:
            buf = f.read()
            hasher.update(buf)
        return hasher.hexdigest()

    def is_in_whitelist(self, md5_hash):
        if os.path.exists("bd\\wl.vrb"):
            with open("bd\\wl.vrb", 'r') as f:
                for line in f:
                    if md5_hash in line.strip():
                        return True
        return False

    def is_in_virus_db(self, md5_hash):
        if os.path.exists("bd\\bdk.vrb"):
            with open("bd\\bdk.vrb", 'r') as f:
                for line in f:
                    if md5_hash in line.strip():
                        return True
        return False

    def scan_with_apex(self, file_path):
        result = subprocess.run(
            ["bd\\apex\\APEXScan.exe", "/s=2", f"/f={file_path}"],
            capture_output=True,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        return result.stdout

    def scan_with_t3(self, file_path):
        result = subprocess.run(
            ["bd\\ikarus\\t3scan_w64.exe", file_path],
            capture_output=True,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        for line in result.stdout.splitlines():
            if "Signature" in line:
                return line.split("'")[1]
        return None

    def show_about(self):
        messagebox.showinfo("关于", "枫诗病毒检测工具 V2.2\n版权所有 枫诗科技")

    def save_log(self):
        log_content = self.log_text.get(1.0, tk.END)
        file_path = filedialog.asksaveasfilename(defaultextension=".txt",
                                                 filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if file_path:
            with open(file_path, 'w') as f:
                f.write(log_content)
            messagebox.showinfo("保存日志", f"日志已保存到: {file_path}")

    def confirm_update(self):
        if messagebox.askyesno("确认更新", "是否开始更新？"):
            self.delete_temp_file("apexdata5.7z")
            self.show_progress()
            self.check_update_thread()

    def show_progress(self):
        self.progress_label.config(text="正在更新...")
        self.progress_label.pack(pady=10)
        self.progress_frame.pack(pady=10)

        # 重置进度条和百分比标签
        self.progress_bar_t3['value'] = 0
        self.progress_percentage_t3.config(text="0%")
        self.progress_bar_apex['value'] = 0
        self.progress_percentage_apex.config(text="0%")

    def hide_progress(self):
        self.progress_label.pack_forget()
        self.progress_frame.pack_forget()

    def check_update_thread(self):
        self.update_thread = threading.Thread(target=self.check_update)
        self.update_thread.start()

    def check_update(self):
        try:
            # 创建 T3 和 APEX 更新的线程
            t3_thread = threading.Thread(target=self.update_t3)
            apex_thread = threading.Thread(target=self.update_apex)

            t3_thread.start()
            apex_thread.start()

            t3_thread.join()
            apex_thread.join()

        except Exception as e:
            messagebox.showerror("更新错误", f"更新错误: {str(e)}")
            self.update_apex()  # 更新失败后尝试更新另一个引擎

    def update_t3(self):
        try:
            url_t3 = "http://updates.ikarus.at/cgi-bin/t3download.pl/t3sigs.vdb"
            local_file_t3 = "bd\\ikarus\\t3sigs.vdb"

            self.download_with_progress(url_t3, local_file_t3, self.progress_bar_t3, self.progress_percentage_t3)

        except Exception as e:
            messagebox.showerror("T3更新错误", f"T3更新错误: {str(e)}")

    def update_apex(self):
        try:
            url_apex = "https://secureaplus.secureage.com/download/apexdata5.7z"
            local_file_apex = os.path.join(tempfile.gettempdir(), "apexdata5.7z")

            self.download_with_progress(url_apex, local_file_apex, self.progress_bar_apex, self.progress_percentage_apex)

            # 使用 7zip 解压文件
            seven_zip_path = "bd\\7z.exe"
            extract_path_apex = "bd\\APEX\\models"
            subprocess.run([seven_zip_path, "x", "-y", local_file_apex, f"-o{extract_path_apex}"],
                           capture_output=True,
                           text=True,
                           check=True)

            os.remove(local_file_apex)

        except Exception as e:
            messagebox.showerror("APEX更新错误", f"APEX更新错误: {str(e)}")

    def download_with_progress(self, url, local_file, progress_bar, progress_label):
        response = requests.get(url, stream=True)
        total_size = int(response.headers.get('content-length', 0))
        block_size = 1024  # 1 Kilobyte
        progress_bar['maximum'] = total_size

        with open(local_file, 'wb') as f:
            for data in response.iter_content(block_size):
                if self.stop_update.is_set():
                    return
                f.write(data)
                progress_bar['value'] += len(data)
                percentage = (progress_bar['value'] / total_size) * 100
                progress_label.config(text=f"{percentage:.2f}%")
                progress_bar.update()

    def delete_temp_file(self, file_name):
        temp_file = os.path.join(tempfile.gettempdir(), file_name)
        if os.path.exists(temp_file):
            os.remove(temp_file)

    def on_closing(self):
        if self.update_thread and self.update_thread.is_alive():
            self.stop_update.set()
            self.update_thread.join()
        self.root.destroy()

    def open_db_tool(self):
        db_tool_window = tk.Toplevel(self.root)
        db_tool_window.title("病毒入库工具")
        db_tool_window.geometry("600x400")

        db_tool_label = tk.Label(db_tool_window, text="选择文件或文件夹:", font=self.font)
        db_tool_label.pack(pady=10)

        select_file_button = tk.Button(db_tool_window, text="选择文件", command=self.select_file, font=self.font)
        select_file_button.pack(pady=10)

        select_folder_button = tk.Button(db_tool_window, text="选择文件夹", command=self.select_folder, font=self.font)
        select_folder_button.pack(pady=10)

    def select_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            md5_hash = self.calculate_md5(file_path)
            with open("bd\\bdk.vrb", 'a') as f:
                f.write(md5_hash + "\n")
            messagebox.showinfo("", f"文件 {file_path} 已写入病毒库")

    def select_folder(self):
        folder_path = filedialog.askdirectory()
        if folder_path:
            with open("bd\\bdk.vrb", 'a') as f:
                for root, _, files in os.walk(folder_path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        md5_hash = self.calculate_md5(file_path)
                        f.write(md5_hash + "\n")
            messagebox.showinfo("文件夹选择", f"文件夹 {folder_path} 内所有文件的已写入病毒库")

    def hug(self):
        messagebox.showinfo("抱抱", "给你一个大的抱抱\nmua~~~")

if __name__ == "__main__":
    root = tk.Tk()
    app = VirusScannerApp(root)
    root.mainloop()
