# DNS Monitor

一个功能强大的DNS监控工具，支持DNS流量分析、解析路径追踪和缓存监控。

## 功能特性

### 🚀 核心功能

- **DNS流量监控**: 使用高性能的pcapy-ng + dpkt进行实时DNS数据包捕获和分析
- **解析路径追踪**: 基于BPF过滤器追踪从客户端到递归解析器的完整DNS解析路径
- **缓存监控**: 支持BIND和Unbound DNS服务器的缓存变化监控
- **统一监控**: 集成所有监控功能为统一的监控系统

### 📊 监控能力

- **流量分析**:
  - 实时DNS数据包捕获
  - 查询类型统计
  - 响应代码分析
  - 流量模式识别
  - PCAP文件自动轮转

- **解析路径追踪**:
  - 客户端到解析器的完整路径
  - 中间查询和响应追踪
  - 解析时间统计
  - 超时检测

- **缓存监控**:
  - 实时缓存变化检测
  - 记录添加/删除/修改追踪
  - 缓存统计分析
  - 支持BIND和Unbound

## 安装

### 系统要求

- Python 3.8+
- Linux/Windows系统
- 管理员权限（用于网络数据包捕获）

### 依赖安装

```bash
# 克隆项目
git clone <repository-url>
cd dnsmonitor

# 安装依赖
pip install -e .

# 或者安装开发依赖
pip install -e ".[dev]"
```

### 系统依赖

#### Linux (Ubuntu/Debian)
```bash
sudo apt-get update
sudo apt-get install libpcap-dev python3-dev
```

#### Linux (CentOS/RHEL)
```bash
sudo yum install libpcap-devel python3-devel
# 或者使用 dnf
sudo dnf install libpcap-devel python3-devel
```

#### Windows
- 安装 [WinPcap](https://www.winpcap.org/) 或 [Npcap](https://nmap.org/npcap/)
- 确保以管理员权限运行

## 快速开始

### 1. 生成配置文件

```bash
dnsmonitor generate-config --output config.yaml
```

### 2. 编辑配置文件

```yaml
# config.yaml
log_level: INFO
log_file: dnsmonitor.log

# 启用监控组件
enable_traffic_monitoring: true
enable_resolver_monitoring: true
enable_cache_monitoring: false

# 流量监控配置
traffic_config:
  interface: "eth0"
  output_dir: "./pcap_files"
  max_file_size: 104857600  # 100MB
  max_files: 10

# 解析路径监控配置
resolver_config:
  client_ip: "192.168.1.100"
  resolver_ip: "8.8.8.8"
  timeout: 30

# 缓存监控配置（可选）
cache_config:
  server_type: "bind"  # 或 "unbound"
  interval: 10
  save_changes: true
```

### 3. 启动监控

```bash
# 完整监控
sudo dnsmonitor monitor --config config.yaml

# 仅流量监控
sudo dnsmonitor traffic --interface eth0 --output-dir ./pcap

# 仅解析路径监控
sudo dnsmonitor resolver --client-ip 192.168.1.100 --resolver-ip 8.8.8.8

# 仅缓存监控
sudo dnsmonitor cache --server-type bind --interval 10
```

## 详细使用说明

### 命令行接口

#### 主命令

```bash
dnsmonitor [OPTIONS] COMMAND [ARGS]...
```

**选项**:
- `--config PATH`: 配置文件路径
- `--log-level LEVEL`: 日志级别 (DEBUG, INFO, WARNING, ERROR)
- `--help`: 显示帮助信息

#### 子命令

##### monitor - 综合监控
```bash
dnsmonitor monitor [OPTIONS]
```

启动所有启用的监控组件。

**选项**:
- `--config PATH`: 配置文件路径
- `--daemon`: 后台运行模式

##### traffic - DNS流量监控
```bash
dnsmonitor traffic [OPTIONS]
```

**选项**:
- `--interface TEXT`: 网络接口名称
- `--output-dir PATH`: PCAP文件输出目录
- `--max-file-size INTEGER`: 最大文件大小（字节）
- `--max-files INTEGER`: 最大文件数量
- `--filter TEXT`: BPF过滤器

##### resolver - 解析路径监控
```bash
dnsmonitor resolver [OPTIONS]
```

**选项**:
- `--client-ip TEXT`: 客户端IP地址
- `--resolver-ip TEXT`: 解析器IP地址
- `--timeout INTEGER`: 事务超时时间（秒）

##### cache - 缓存监控
```bash
dnsmonitor cache [OPTIONS]
```

**选项**:
- `--server-type [bind|unbound]`: DNS服务器类型
- `--interval INTEGER`: 监控间隔（秒）
- `--save-changes`: 保存缓存变化到文件

##### generate-config - 生成配置文件
```bash
dnsmonitor generate-config [OPTIONS]
```

**选项**:
- `--output PATH`: 输出文件路径

##### version - 显示版本
```bash
dnsmonitor version
```

### 配置文件详解

#### 基本配置

```yaml
# 日志配置
log_level: INFO          # DEBUG, INFO, WARNING, ERROR
log_file: dnsmonitor.log # 日志文件路径，不设置则输出到控制台

# 监控组件开关
enable_traffic_monitoring: true    # 启用流量监控
enable_resolver_monitoring: true   # 启用解析路径监控
enable_cache_monitoring: false     # 启用缓存监控
```

#### 流量监控配置

```yaml
traffic_config:
  interface: "eth0"                 # 网络接口
  bpf_filter: "port 53"            # BPF过滤器
  output_dir: "./pcap_files"       # 输出目录
  max_file_size: 104857600         # 最大文件大小（100MB）
  max_files: 10                    # 最大文件数量
  enable_statistics: true          # 启用统计
  statistics_interval: 60          # 统计间隔（秒）
```

#### 解析路径监控配置

```yaml
resolver_config:
  client_ip: "192.168.1.100"       # 客户端IP
  resolver_ip: "8.8.8.8"           # 解析器IP
  timeout: 30                      # 事务超时（秒）
  save_transactions: true          # 保存事务记录
```

#### 缓存监控配置

```yaml
cache_config:
  server_type: "bind"              # DNS服务器类型: bind 或 unbound
  interval: 10                     # 监控间隔（秒）
  save_changes: true               # 保存变化记录
  
  # BIND特定配置
  bind_rndc_key: "/etc/bind/rndc.key"
  bind_dump_file: "/var/cache/bind/named_dump.db"
  
  # 分析服务器配置
  enable_analysis_server: false    # 启用TCP分析服务器
  analysis_port: 9999              # 分析服务器端口
```

## 输出文件

### 流量监控输出

- **PCAP文件**: `traffic_YYYYMMDD_HHMMSS.pcap`
- **统计文件**: `traffic_stats_YYYYMMDD_HHMMSS.json`

### 解析路径监控输出

- **事务记录**: `resolver_monitor_results_YYYYMMDD_HHMMSS.json`

### 缓存监控输出

- **缓存变化**: `cache_changes_YYYYMMDD_HHMMSS.json`
- **监控统计**: `cache_monitor_stats_YYYYMMDD_HHMMSS.json`

## 使用场景

### 1. DNS流量分析

监控网络中的DNS查询模式，识别异常流量：

```bash
sudo dnsmonitor traffic --interface eth0 --output-dir ./dns_traffic
```

### 2. DNS解析性能分析

追踪DNS查询的完整解析路径，分析解析性能：

```bash
sudo dnsmonitor resolver --client-ip 192.168.1.100 --resolver-ip 8.8.8.8
```

### 3. DNS缓存行为分析

监控DNS服务器缓存的变化，了解缓存行为：

```bash
sudo dnsmonitor cache --server-type bind --interval 5 --save-changes
```

### 4. 综合DNS监控

同时启用所有监控功能：

```bash
sudo dnsmonitor monitor --config comprehensive_config.yaml
```

## 故障排除

### 常见问题

#### 1. 权限错误
```
PermissionError: [Errno 1] Operation not permitted
```

**解决方案**: 使用管理员权限运行：
```bash
sudo dnsmonitor monitor --config config.yaml
```

#### 2. 网络接口不存在
```
OSError: No such device exists
```

**解决方案**: 检查可用的网络接口：
```bash
# Linux
ip link show
# 或
ifconfig

# Windows
ipconfig
```

#### 3. PCAP库未安装
```
ImportError: No module named 'pcapy'
```

**解决方案**: 安装系统依赖和Python包：
```bash
# Ubuntu/Debian
sudo apt-get install libpcap-dev
pip install pcapy-ng

# CentOS/RHEL
sudo yum install libpcap-devel
pip install pcapy-ng
```

#### 4. DNS服务器连接失败
```
Failed to dump BIND cache: rndc: connect failed
```

**解决方案**: 检查BIND配置和rndc密钥：
```bash
# 检查rndc配置
sudo rndc status

# 检查密钥文件权限
ls -la /etc/bind/rndc.key
```

### 调试模式

启用详细日志进行调试：

```bash
dnsmonitor monitor --config config.yaml --log-level DEBUG
```

## 性能优化

### 1. 流量监控优化

- 使用合适的BPF过滤器减少不必要的数据包捕获
- 调整文件大小和数量限制
- 在高流量环境中考虑使用更快的存储

### 2. 解析路径监控优化

- 调整超时时间以平衡准确性和性能
- 在高并发环境中增加缓冲区大小

### 3. 缓存监控优化

- 根据缓存变化频率调整监控间隔
- 在大型缓存环境中考虑采样监控

## 开发

### 项目结构

```
dnsmonitor/
├── src/dnsmonitor/
│   ├── __init__.py          # 包初始化
│   ├── cli.py               # 命令行接口
│   ├── config.py            # 配置管理
│   ├── utils.py             # 工具函数
│   ├── monitor.py           # 主监控模块
│   ├── traffic.py           # 流量监控
│   ├── resolver.py          # 解析路径监控
│   └── cache.py             # 缓存监控
├── tests/                   # 测试文件
├── docs/                    # 文档
├── examples/                # 示例配置
├── pyproject.toml           # 项目配置
└── README.md               # 项目说明
```

### 运行测试

```bash
# 安装开发依赖
pip install -e ".[dev]"

# 运行测试
pytest tests/

# 运行代码检查
black src/
mypy src/
```

## 许可证

MIT License

## 贡献

欢迎提交Issue和Pull Request！

## 更新日志

### v1.0.0
- 初始版本发布
- 支持DNS流量监控
- 支持解析路径追踪
- 支持BIND和Unbound缓存监控
- 提供命令行接口和配置文件支持