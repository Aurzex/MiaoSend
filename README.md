# 🐱 **喵传 MiaoSend**  

**萌萌哒文件上传/下载工具 | 支持分块传输 & 历史记录**  

<div align="center">

```
  /\_/\  
 ( •̀ ω •́ )✧  
  / >📁< \  
 喵传 v1.0  
```
[![Rust](https://img.shields.io/badge/Made%20with-Rust-orange.svg)](https://www.rust-lang.org/)

</div>

## ✨ 功能特点  

- 🐾 **萌萌哒体验**：猫咪主题进度条与提示音  
- ⚡ **闪电传输**：自动分块上传大文件（40MB/块）  
- 📚 **历史记忆**：记录所有上传/下载任务  
- 🔒 **安全登录**：支持账号密码认证  
- 🧩 **智能合并**：一键合并分块下载的文件  
- 🛠 **多端支持**：Windows/macOS/Linux全平台  

## 🚀 快速开始  

### 安装方式  

```bash
# 通过Cargo安装 (需先安装Rust环境)
cargo install miaosend
```

### 基本使用  

```bash
# 登录账号
miaosend login -i 你的邮箱 -p 密码

# 上传文件（自动分块）
miaosend upload -f 大文件.zip -s 保存路径

# 下载文件（支持进度条）
miaosend download -u 文件URL -o 保存位置

# 合并分块文件
miaosend merge -o 合并后文件.zip -c 分块1.7z.001 分块2.7z.002...

# 查看历史记录
miaosend history
```

## 🧶 技术架构  

```mermaid
graph LR
    A[用户命令] --> B(解析参数)
    B --> C{操作类型}
    C -->|上传| D[分块压缩]
    C -->|下载| E[流式下载]
    D --> F[并行上传]
    F --> G[记录历史]
    E --> G
```

## 🐟 贡献指南  

欢迎投喂小鱼干（提交PR）！  
1. Fork本仓库  
2. 创建新分支 (`git checkout -b feature/新功能`)  
3. 提交修改 (`git commit -am '添加萌萌的新功能'`)  
4. 推送分支 (`git push origin feature/新功能`)  
5. 发起Pull Request  

## 📜 开源协议  

GNU License - 详见 [LICENSE](LICENSE) 文件  

---

<div align="center">
<sub>🐈 用 Rust 编写的可爱传输工具 | 喵~有问题请提交 </sub>
<a href="https://github.com/yourname/miaosend/issues">Issue</a>
</div>

---

