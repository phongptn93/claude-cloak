<div align="center">

# Claude Cloak

**Dùng chung một tài khoản Claude Code trên nhiều máy Windows — không bị phát hiện.**

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)

<img src="https://img.shields.io/badge/Windows-0078D6?logo=windows&logoColor=white" alt="Windows"> <img src="https://img.shields.io/badge/Claude_Code-VS_Code-7C3AED?logo=visual-studio-code" alt="VS Code">

---

*Proxy nội bộ trong suốt — giả lập tất cả các máy thành một thiết bị duy nhất với Anthropic.*

<img src="assets/screenshot.png" alt="Claude Proxy" width="700">

</div>

## Cách hoạt động

- **Máy đầu tiên** đăng nhập Claude Code → proxy tự động bắt 14 identity headers → lưu vào `.env`
- **Các máy khác** copy file `.env` → proxy inject headers đã lock vào mọi request
- **Authorization header** (auth token) luôn pass-through thẳng từ mỗi request — không lưu, không chia sẻ

Kết quả: tất cả máy gửi cùng một fingerprint thiết bị tới Anthropic.

## Tính năng

| Tính năng | Mô tả |
|-----------|-------|
| **Auto-Capture** | Tự động bắt 14 identity headers từ request đầu tiên của Claude Code |
| **14 Headers Locked** | user-agent, session-id, stainless-*, anthropic-beta, v.v. |
| **Header Warning** | Cảnh báo khi phát hiện header lạ chưa có trong danh sách lock |
| **Auto-Config** | Tự động set `ANTHROPIC_BASE_URL` trong settings của Claude Code |
| **Zero Config** | Chỉ cần chạy `start.bat` — mọi thứ còn lại tự động |

## Quick Start

### Máy đầu tiên (thiết lập một lần)

```bash
cd client
install.bat       # Cài dependencies
start.bat         # Khởi động proxy + tự config Claude Code
```

Mở Claude Code trong VS Code và **đăng nhập bình thường**. Proxy tự động bắt identity headers từ request đầu tiên.

### Các máy khác

```bash
cd client
install.bat       # Cài dependencies
```

Copy file **`.env`** từ máy đầu tiên sang, sau đó:

```bash
start.bat         # Khởi động proxy
```

Proxy sẽ inject identity headers đã lock. Mỗi máy vẫn đăng nhập bằng tài khoản của mình — chỉ fingerprint thiết bị là giống nhau.

## Security

### Headers Spoofed

Tất cả máy sẽ gửi cùng một fingerprint thiết bị:

| Header | Purpose |
|--------|---------|
| `user-agent` | Client version + OS |
| `x-claude-code-session-id` | Session identifier |
| `x-app` | Client type |
| `anthropic-beta` | Feature flags |
| `anthropic-version` | API version |
| `anthropic-dangerous-direct-browser-access` | Browser flag |
| `x-stainless-os` | Operating system |
| `x-stainless-arch` | CPU architecture |
| `x-stainless-runtime` | Runtime environment |
| `x-stainless-runtime-version` | Runtime version |
| `x-stainless-lang` | SDK language |
| `x-stainless-package-version` | SDK version |
| `accept-encoding` | Compression support |
| `sec-fetch-mode` | Fetch metadata |

## Project Structure

```
client/
├── proxy.py           # Main proxy server (FastAPI)
├── setup_claude.py    # Auto-config Claude Code settings
├── tray_app.py        # Windows system tray app
├── start.bat          # Launch script (kill old port + start)
├── install.bat        # Dependency installer
├── .env.example       # Config template
├── .env               # Config with captured data (git-ignored)
└── requirements.txt   # Python dependencies
```

## Requirements

- **Python** 3.10+
- **Windows** 10/11
- **Claude Code** (VS Code extension or CLI)

## Troubleshooting

| Vấn đề | Giải pháp |
|--------|-----------|
| Port 9999 đang bị dùng | `start.bat` tự kill process cũ. Hoặc đổi `LOCAL_PORT` trong `.env` |
| Token hết hạn (401) | Đăng nhập lại trên bất kỳ máy nào, copy `.env` sang các máy khác |
| Headers lạ xuất hiện | Kiểm tra console — proxy sẽ cảnh báo header chưa có trong danh sách lock |
| Response rỗng từ API | Kiểm tra console proxy để xem status code lỗi |

---

<div align="center">
<sub>Xây dựng cho việc dùng Claude Code trên nhiều máy Windows.</sub>
</div>
