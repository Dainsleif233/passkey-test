# Passkey 插件

为 Blessing Skin Server 6 增加 WebAuthn/FIDO2 通行密钥登录方式。

## 功能特性

- 无密码登录：使用生物识别或安全密钥登录
- 无用户名登录：浏览器自动选择已注册的通行密钥
- 用户管理：注册、重命名、删除通行密钥
- 管理员配置：RP ID、用户验证级别等设置

## 环境要求

- Blessing Skin Server ^6.0
- PHP ^8.1
- 扩展：`openssl`、`mbstring`
- **必须使用 HTTPS**（localhost 除外）

## 安装步骤

### 方式一：从 Release 下载（推荐）

1. 从 [Releases](https://github.com/your-username/passkey/releases) 下载最新的 `passkey-vX.X.X.zip` 文件
2. 解压到 Blessing Skin 的 `plugins/` 目录
3. 在后台插件管理中启用 "Passkey" 插件

### 方式二：从源码安装

1. 克隆或下载本仓库
2. 在插件目录中运行 `composer install`
3. 将 `passkey` 目录放入 Blessing Skin 的 `plugins/` 目录
4. 在后台插件管理中启用 "Passkey" 插件

> ⚠️ **重要**：从源码安装时，第2步是必须的，否则插件无法工作。

## 配置说明

管理员可在后台插件配置中调整以下选项：

| 选项 | 默认值 | 说明 |
|------|--------|------|
| RP ID | 当前域名 | WebAuthn 依赖方 ID |
| RP 名称 | 站点名称 | 依赖方显示名称 |
| 用户验证 | Preferred | 认证时的用户验证级别 |
| 显示登录按钮 | 开启 | 在登录页显示通行密钥按钮 |
| 记住登录 | 开启 | 记住通行密钥登录会话 |
| 最大通行密钥数 | 5 | 每用户可注册的最大数量 |

## 工作原理

### 注册流程

1. 用户在管理页面点击"添加新通行密钥"
2. 浏览器调用 `navigator.credentials.create()` 创建新凭据
3. 服务器验证并存储凭据信息

### 登录流程

1. 登录页显示"使用通行密钥登录"按钮
2. 浏览器调用 `navigator.credentials.get()` 获取凭据
3. 服务器验证签名并登录用户

### 技术实现

- 使用 [lbuchs/webauthn](https://github.com/lbuchs/WebAuthn) 库处理 WebAuthn 协议
- 凭据 ID 使用 SHA-256 哈希存储，避免唯一索引长度问题
- Challenge 一次性使用，5分钟过期
- 支持无用户名/可发现凭据登录

## 常见问题

### Q: 为什么看不到登录按钮？
A: 可能原因：
1. 浏览器不支持 WebAuthn（需要 Chrome 67+、Firefox 60+、Safari 13+）
2. 页面未使用 HTTPS（localhost 除外）
3. 管理员在插件配置中禁用了登录按钮

### Q: 忘记注册了通行密钥怎么办？
A: 使用密码登录后，在"我的通行密钥"页面注册新的通行密钥。

### Q: 插件停用后数据会丢失吗？
A: 不会。插件停用或删除时不会删除数据表，重新启用后数据仍然存在。

### Q: 如何支持多个域名？
A: 在插件配置中显式设置 RP ID 为所需域名（如 `example.com`）。

## 安全说明

- Challenge 一次性使用，防止重放攻击
- 签名验证完全由 WebAuthn 库处理
- 公钥和凭据 ID 不会记录到日志
- 封禁用户无法通过通行密钥登录

## 开发说明

### 文件结构

```
passkey/
├── assets/passkey.js          # 前端 JavaScript
├── lang/{en,zh_CN}/           # 语言文件
├── src/
│   ├── Controllers/           # 控制器
│   ├── Models/                # 数据模型
│   └── Support/               # 辅助类
└── views/                     # Twig 视图
```

### 构建要求

- Node.js（仅用于语法检查，无构建步骤）
- PHP（用于语法检查）

### 语法检查

```bash
# PHP 语法检查
find . -name "*.php" -exec php -l {} \;

# JavaScript 语法检查
node --check assets/passkey.js
```

## 协议

本插件使用 [GPL-3.0-only](LICENSE) 协议。

## 致谢

- [lbuchs/webauthn](https://github.com/lbuchs/WebAuthn) - PHP WebAuthn 库
- [Blessing Skin](https://github.com/BSCommunity/blessing-skin-server) - 我的世界皮肤站