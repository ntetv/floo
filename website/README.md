# Floo Windows GUI Shell Prototype

`website/` 现在既是 Floo 的前端原型目录，也是 Windows 管理器 GUI 壳的开发区。

当前目标是尽快提供一个可双击、可评审交互的 `floo-windows.exe` 测试壳，方便在 Windows 上确认以下界面是否合理：

- 中文状态面板
- 实例列表与实例详情
- 导入客户端弹窗
- 添加实例弹窗（客户端 / 服务端切换）
- 日志查看弹窗
- 实例操作按钮布局

## 当前状态

- React + Vite 页面已收敛为单窗口桌面管理器布局
- Electron 负责桌面壳封装
- 目前仍是 mock 数据 / mock 操作，不会真正调用 `flooc.exe` / `floos.exe`
- 后续会再接入 `import-client`、`status`、`list`、`start/stop/restart`、`logs`、`enable/disable autostart`

## 开发要求

- Node.js 20+
- npm

## 安装依赖

```bash
npm install
```

## Web 原型调试

```bash
npm run dev
```

默认地址：`http://127.0.0.1:5173`

## 桌面壳调试

```bash
npm run dev:desktop
```

这个命令会：

1. 启动 Vite 开发服务器
2. 等待本地端口就绪
3. 打开 Electron 桌面窗口

## 构建 Web 静态资源

```bash
npm run build
```

输出目录：`dist/`

## 构建桌面壳目录产物

```bash
npm run build:desktop
```

这个命令会先构建前端，再生成当前平台的 Electron unpacked 目录产物，用来验证桌面壳打包配置。

## 构建 Windows 单文件 GUI 壳

```bash
npm run build:desktop:win
```

预期产物：`release/windows-gui/floo-windows.exe`

说明：

- 该命令主要面向 Windows 环境或 Windows CI runner
- 当前 GitHub workflow 会在 Windows runner 上构建该产物，再并入主 release zip
- 也可以直接运行专用 workflow `.github/workflows/windows-gui.yml`，单独生成可下载的 `floo-windows.exe` 测试产物

## GitHub Pages

`website/` 仍可通过 `.github/workflows/deploy-website.yml` 构建并发布静态原型页面。

由于 Vite 已改为相对资源路径，页面既可作为桌面壳 renderer，也可继续用于静态托管预览。

## 目录说明

```text
website/
├── electron/
│   └── main.cjs          # Electron 主进程入口
├── src/
│   ├── App.jsx           # Windows GUI 壳主界面
│   ├── App.css           # GUI 壳样式
│   ├── index.css         # 全局基础样式
│   └── main.jsx          # React 入口
├── index.html            # HTML 模板
├── vite.config.js        # Vite 配置（桌面壳 + 静态托管共用）
└── package.json          # 前端与桌面壳脚本
```

## 下一阶段

后续确认 GUI 交互通过后，再补齐真正的后端逻辑：

- 读取 Windows 受管目录
- 获取实例状态与日志
- 导入客户端
- 添加服务端 / 客户端实例
- 启停与重启实例
- 自启动开关
