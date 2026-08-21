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
- **必须使用 HTTPS**

## 安装步骤

1. 从 [Releases](https://github.com/Dainsleif233/skin-Passkey/releases) 下载最新的 `passkey-X.X.X.zip` 文件
2. 在后台插件管理中上传或解压到 Blessing Skin 的 `plugins/` 目录
3. 在后台插件管理中启用 "Passkey" 插件

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

## 常见问题

### Q: 为什么看不到登录按钮？
A: 可能原因：
1. 浏览器不支持 WebAuthn（需要 Chrome 67+、Firefox 60+、Safari 13+）
2. 页面未使用 HTTPS
3. 管理员在插件配置中禁用了登录按钮

### Q: 忘记注册了通行密钥怎么办？
A: 使用密码登录后，在"通行密钥"页面注册新的通行密钥。

### Q: 插件停用后数据会丢失吗？
A: 不会。插件停用或删除时不会删除数据表，重新启用后数据仍然存在。

### Q: 如何支持多个域名？
A: 在插件配置中显式设置 RP ID 为所需域名。

## 安全说明

- Challenge 一次性使用，防止重放攻击
- 签名验证完全由 WebAuthn 库处理
- 公钥和凭据 ID 不会记录到日志
- 封禁用户、未验证邮箱用户无法通过通行密钥登录

## 协议

本插件使用 [GPL-3.0-only](LICENSE) 协议。

## 致谢

- [lbuchs/webauthn](https://github.com/lbuchs/WebAuthn) - PHP WebAuthn 库
- [Blessing Skin](https://github.com/BS-Community/blessing-skin-server) - 开源 PHP Minecraft 皮肤站
