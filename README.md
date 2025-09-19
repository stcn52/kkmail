# KKMail - 自定义域名邮箱服务

基于 Cloudflare Workers 和 Resend 的无服务器邮箱服务，支持自定义域名发送和接收邮件。

## 🌟 功能特性

- 📧 **自定义域名邮件发送** - 使用 Resend API 发送邮件
- 📬 **邮件接收和路由** - 接收发送到您域名的邮件
- 🔄 **邮件别名** - 支持邮件转发和别名
- 🔐 **JWT 认证** - 安全的 API 访问控制
- 📊 **发送日志** - 跟踪邮件发送状态
- 🗄️ **D1 数据库** - 存储邮件和用户数据
- 🚀 **自动部署** - GitHub Actions 自动部署到 Cloudflare
- 🎛️ **Web 管理界面** - 完整的后台管理系统
- 🔑 **用户 API Token** - 基于用户的 API 访问控制
- 📤 **简化 API** - 无需指定发件人的简单邮件发送接口

## 🛠️ 技术栈

- **Cloudflare Workers** - 无服务器计算平台
- **Cloudflare D1** - SQLite 数据库
- **Resend** - 邮件发送服务
- **GitHub Actions** - 持续集成和部署

## 📋 前置要求

1. **Cloudflare 账户** - 需要 Workers 和 D1 访问权限
2. **Resend 账户** - 用于发送邮件
3. **自定义域名** - 配置 DNS 记录
4. **GitHub 仓库** - 用于代码管理和自动部署

## 🚀 快速开始

### 1. 克隆项目

```bash
git clone https://github.com/stcn52/kkmail.git
cd kkmail
npm install
```

### 2. Cloudflare 配置

#### 创建 D1 数据库
```bash
# 安装 Wrangler CLI
npm install -g wrangler

# 登录 Cloudflare
wrangler login

# 创建 D1 数据库
wrangler d1 create kkmail-db
```

#### 创建 KV 命名空间
```bash
wrangler kv:namespace create "KV"
```

#### 创建 R2 存储桶
```bash
wrangler r2 bucket create kkmail-storage
```

### 3. 配置环境变量

在 `wrangler.toml` 文件中更新以下配置：

```toml
# 更新数据库 ID
[[env.production.d1_databases]]
binding = "DB"
database_name = "kkmail-db"
database_id = "你的数据库ID"

# 更新 KV ID
[[env.production.kv_namespaces]]
binding = "KV"
id = "你的KV命名空间ID"
```

设置环境变量：
```bash
wrangler secret put RESEND_API_KEY --env production
wrangler secret put JWT_SECRET --env production
wrangler secret put ADMIN_EMAIL --env production
wrangler secret put DOMAIN --env production          # 你的服务域名，如：mail.yourdomain.com
wrangler secret put EMAIL_DOMAIN --env production    # 你的邮件域名，如：yourdomain.com
```

### 4. Resend 配置

1. 在 [Resend](https://resend.com) 创建账户
2. 验证您的域名
3. 创建 API 密钥
4. 配置 DNS 记录（SPF, DKIM, DMARC）

### 5. GitHub Actions 配置

在 GitHub 仓库设置中添加以下 Secrets：

- `CLOUDFLARE_API_TOKEN` - Cloudflare API 令牌
- `CLOUDFLARE_ACCOUNT_ID` - Cloudflare 账户 ID
- `DOMAIN` - 您的域名

### 6. 部署

```bash
# 本地开发
npm run dev

# 部署到生产环境
npm run deploy

# 初始化数据库
curl -X POST "https://mail.yourdomain.com/api/init"
```

## 🔧 API 文档

### 认证

所有 API 请求需要在 Header 中包含认证令牌：

```bash
Authorization: Bearer your_jwt_token
```

### 登录

```bash
POST /api/auth/login
Content-Type: application/json

{
  "email": "admin@yourdomain.com",
  "password": "your_password"
}
```

### 发送邮件（管理员接口）

```bash
POST /api/send
Authorization: Bearer your_jwt_token
Content-Type: application/json

{
  "from": "noreply@yourdomain.com",
  "to": "recipient@example.com",
  "subject": "Test Email",
  "html": "<h1>Hello World</h1>",
  "text": "Hello World"
}
```

### 简化邮件发送（用户 API）

```bash
POST /api/send-simple
X-API-Token: your_user_api_token
Content-Type: application/json

{
  "to": "recipient@example.com",
  "subject": "Test Email",
  "text": "Hello World",
  "html": "<h1>Hello World</h1>"  // 可选
}
```

注：使用 `/api/send-simple` 时发件人将自动使用 API Token 对应用户的邮箱地址。

### 获取邮件列表

```bash
GET /api/emails?limit=50&offset=0&status=received
Authorization: Bearer your_jwt_token
```

### 获取单个邮件

```bash
GET /api/emails/{emailId}
Authorization: Bearer your_jwt_token
```

## 📁 项目结构

```
kkmail/
├── src/
│   ├── index.js         # 主要的 Worker 代码（包含管理界面）
│   ├── resend.js        # Resend API 集成
│   ├── auth.js          # 认证服务
│   └── jwt.js           # JWT 工具函数
├── schemas/
│   └── db.sql          # 数据库模式
├── .github/
│   └── workflows/
│       └── deploy.yml  # GitHub Actions 部署配置
├── wrangler.toml       # Cloudflare Workers 配置
├── package.json        # 项目依赖
└── README.md          # 项目文档
```

## 🎛️ Web 管理界面

访问 `https://mail.yourdomain.com/admin` 或 `https://mail.yourdomain.com/` 进入管理界面。

### 功能模块

- **仪表板** - 系统概览和统计信息
- **邮件管理** - 查看接收的邮件列表
- **用户管理** - 创建和管理用户，生成 API Token
- **邮件别名** - 配置邮件转发和别名
- **发送邮件** - 通过界面直接发送邮件

### 用户 API Token 管理

1. 在用户管理页面为每个用户生成独立的 API Token
2. 用户可以使用自己的 Token 调用 `/api/send-simple` 接口
3. 发件人将自动使用 Token 对应用户的邮箱地址
4. 支持 API 测试功能，可直接在管理界面测试 Token

## 🔒 安全配置

### DNS 记录配置

为您的域名添加以下 DNS 记录：

```
# MX 记录（邮件接收）
MX @ route1.mx.cloudflare.net. 1
MX @ route2.mx.cloudflare.net. 2

# SPF 记录
TXT @ "v=spf1 include:spf.resend.com ~all"

# DKIM 记录（从 Resend 获取）
TXT resend._domainkey "v=DKIM1; k=rsa; p=your_dkim_public_key"

# DMARC 记录
TXT _dmarc "v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com"

# Worker 路由（用于管理界面）
CNAME mail yourdomain.workers.dev
```

### 环境变量

- `RESEND_API_KEY` - Resend API 密钥
- `JWT_SECRET` - JWT 签名密钥（建议使用强随机字符串）
- `ADMIN_EMAIL` - 管理员邮箱地址
- `DOMAIN` - 服务域名（如：mail.yourdomain.com）
- `EMAIL_DOMAIN` - 邮件域名（如：yourdomain.com）

### 安全建议

1. **使用强密码** - 管理员账户密码应足够复杂
2. **定期更换密钥** - 定期更新 JWT_SECRET 和 API 密钥
3. **API Token 管理** - 定期检查和撤销不必要的 API Token
4. **访问控制** - 限制管理界面的访问来源
5. **日志监控** - 定期检查发送日志和异常活动

## 📊 监控和日志

### Cloudflare 仪表板

- Workers 执行日志
- D1 数据库查询统计
- 请求分析和错误监控

### Resend 仪表板

- 邮件发送统计
- 投递状态跟踪
- 退信和投诉管理

## 🐛 故障排除

### 常见问题

1. **邮件发送失败**
   - 检查 Resend API 密钥
   - 验证域名配置
   - 检查 DNS 记录

2. **邮件接收失败**
   - 确认 MX 记录配置
   - 检查 Cloudflare Email Routing 设置
   - 验证 Worker 绑定

3. **认证失败**
   - 检查 JWT_SECRET 配置
   - 验证令牌有效期
   - 确认用户权限

4. **API Token 生成失败**
   - 确认用户已正确创建
   - 检查数据库连接
   - 验证 Worker 部署状态

5. **管理界面无法访问**
   - 检查域名 DNS 解析
   - 确认 Worker 路由配置
   - 验证 Cloudflare 代理状态

### 调试命令

```bash
# 查看 Worker 日志
wrangler tail --env production

# 测试数据库连接
wrangler d1 execute kkmail-db --env production --command="SELECT * FROM users LIMIT 1"

# 检查环境变量
wrangler secret list --env production

# 测试 API 接口
curl -X POST "https://mail.yourdomain.com/api/send-simple" \
  -H "X-API-Token: your_token" \
  -H "Content-Type: application/json" \
  -d '{"to":"test@example.com","subject":"Test","text":"Hello"}'
```

## 📈 使用示例

### cURL 示例

```bash
# 获取用户 API Token（管理员权限）
curl -X GET "https://mail.yourdomain.com/api/user-token/1" \
  -H "Authorization: Bearer admin_jwt_token"

# 使用用户 Token 发送邮件
curl -X POST "https://mail.yourdomain.com/api/send-simple" \
  -H "X-API-Token: kkmail_abc123def456" \
  -H "Content-Type: application/json" \
  -d '{
    "to": "recipient@example.com",
    "subject": "Hello from KKMail",
    "text": "这是一封测试邮件",
    "html": "<h1>这是一封测试邮件</h1>"
  }'
```

### JavaScript 示例

```javascript
// 发送邮件
async function sendEmail(token, emailData) {
  const response = await fetch('https://mail.yourdomain.com/api/send-simple', {
    method: 'POST',
    headers: {
      'X-API-Token': token,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(emailData)
  });

  return await response.json();
}

// 使用示例
const result = await sendEmail('kkmail_abc123def456', {
  to: 'user@example.com',
  subject: 'Welcome!',
  text: 'Welcome to our service!'
});
```

## 🤝 贡献

欢迎提交 Issues 和 Pull Requests！

## 📄 许可证

MIT License

## 🔗 相关链接

- [Cloudflare Workers 文档](https://developers.cloudflare.com/workers/)
- [Cloudflare D1 文档](https://developers.cloudflare.com/d1/)
- [Resend 文档](https://resend.com/docs)
- [Email Routing 文档](https://developers.cloudflare.com/email-routing/)

---

💡 **提示**: 确保在生产环境中使用强密码和安全的 JWT 密钥！

🎯 **当前部署**: https://mail.yourdomain.com