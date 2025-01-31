# 枫诗病毒检测工具

### 简介
利用python编写的一款多引擎病毒检测工具。

### 运行环境
* Windows 7+（不含WinServer）
* Unix系统的Wine容器内

### 查杀引擎
* 本地MD5
* APEX
* ikarus(T3)

### 下载源码前，请阅读
1.本源码***不含病毒库文件***(运行目录bd文件夹下的所有文件)，需要自行下载病毒库文件并放置在运行目录bd文件夹下

2.关于病毒库文件夹内相关文件的说明：
> bdk.vrb                   ------     本地MD5(可以通过主页面的“病毒入库工具”写入数据)
> 
> wl.vrb                    ------     本地白名单(MD5，已被废弃)
> 
> 7z.exe                    ------     7zip命令行解压关键组件，用于解压APEX模型数据
> 
> 7z.dll                    ------     7zip命令行解压关键组件，配合7z.exe运行
> 
> \APEX\APEX*.*             ------     APEX命令行组件
> 
> \APEX\models\*.*          ------     APEX模型和数据文件
> 
> \ikarus\t3scan_w64.exe    ------     T3命令行关键组件
> 
> \ikarus\t3_w64.dll        ------     T3命令行关键组件，配合t3scan_w64.exe运行
> 
> \ikarus\t3sigs.vdb        ------     T3病毒库

3.仅供个人研究使用，禁止商用
