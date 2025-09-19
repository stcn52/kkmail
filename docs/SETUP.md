# KKMail 部署配置指南

## 📋 部署清单

### Phase 1: 准备工作

- [ ] 注册 Cloudflare 账户
- [ ] 注册 Resend 账户
- [ ] 准备自定义域名
- [ ] Fork GitHub 仓库

### Phase 2: Cloudflare 配置

#### 2.1 安装 Wrangler CLI

```bash
npm install -g wrangler
wrangler login
```

#### 2.2 创建 D1 数据库

```bash
wrangler d1 create kkmail-db
```

记录返回的数据库 ID，更新 `wrangler.toml` 文件。

#### 2.3 创建 KV 命名空间

```bash
wrangler kv:namespace create "KV" --env production
```

记录返回的 ID，更新 `wrangler.toml` 文件。

#### 2.4 创建 R2 存储桶

```bash
wrangler r2 bucket create kkmail-storage
```

#### 2.5 设置环境变量

```bash
# Resend API 密钥
wrangler secret put RESEND_API_KEY --env production

# JWT 签名密钥（生成一个强随机字符串）
wrangler secret put JWT_SECRET --env production

# 管理员邮箱
wrangler secret put ADMIN_EMAIL --env production
```

### Phase 3: Resend 配置

#### 3.1 域名验证

1. 登录 [Resend 控制台](https://resend.com/domains)
2. 添加您的域名
3. 配置以下 DNS 记录：

```
# SPF 记录
TXT @ "v=spf1 include:spf.resend.com ~all"

# DKIM 记录（从 Resend 获取具体值）
TXT resend._domainkey "v=DKIM1; k=rsa; p=YOUR_DKIM_PUBLIC_KEY"

# DMARC 记录
TXT _dmarc "v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com"
```

#### 3.2 创建 API 密钥

1. 在 Resend 控制台创建新的 API 密钥
2. 选择适当的权限（发送邮件）
3. 保存密钥并设置为环境变量

### Phase 4: 邮件接收配置

#### 4.1 配置 MX 记录

```
MX @ route1.mx.cloudflare.net. 1
MX @ route2.mx.cloudflare.net. 2
MX @ route3.mx.cloudflare.net. 3
```

#### 4.2 启用 Email Routing

1. 登录 Cloudflare 控制台
2. 选择您的域名
3. 启用 Email Routing
4. 配置路由规则

### Phase 5: GitHub Actions 配置

#### 5.1 设置 Repository Secrets

在 GitHub 仓库的 Settings > Secrets and variables > Actions 中添加：

```
CLOUDFLARE_API_TOKEN=your_cloudflare_api_token
CLOUDFLARE_ACCOUNT_ID=your_cloudflare_account_id
DOMAIN=yourdomain.com
```

#### 5.2 获取 Cloudflare API Token

1. 访问 [Cloudflare API Tokens](https://dash.cloudflare.com/profile/api-tokens)
2. 创建自定义令牌，权限包括：
   - Zone:Zone:Read
   - Zone:DNS:Edit
   - User:User Details:Read
   - Account:Cloudflare Workers:Edit
   - Account:D1:Edit

### Phase 6: 部署和初始化

#### 6.1 本地测试

```bash
npm install
npm run dev
```

#### 6.2 部署到生产环境

```bash
npm run deploy
```

#### 6.3 初始化数据库

```bash
curl -X POST "https://kkmail.yourdomain.com/api/init"
```

#### 6.4 创建管理员用户

数据库初始化后，需要手动设置管理员密码：

```bash
# 使用 wrangler 执行 SQL
wrangler d1 execute kkmail-db --env production --command="
UPDATE users
SET password_hash = 'your_hashed_password'
WHERE email = 'admin@yourdomain.com'
"
```

### Phase 7: 测试验证

#### 7.1 测试登录

```bash
curl -X POST "https://kkmail.yourdomain.com/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@yourdomain.com",
    "password": "your_password"
  }'
```

#### 7.2 测试邮件发送

```bash
curl -X POST "https://kkmail.yourdomain.com/api/send" \
  -H "Authorization: Bearer your_jwt_token" \
  -H "Content-Type: application/json" \
  -d '{
    "from": "noreply@yourdomain.com",
    "to": "test@example.com",
    "subject": "Test Email",
    "text": "This is a test email from KKMail"
  }'
```

#### 7.3 测试邮件接收

发送邮件到您的域名任意邮箱地址，检查是否正确接收和存储。

## 🔧 高级配置

### 自定义域名绑定

```bash
# 绑定自定义域名到 Worker
wrangler custom-domains add kkmail.yourdomain.com --env production
```

### 配置邮件别名

```bash
curl -X POST "https://kkmail.yourdomain.com/api/aliases" \
  -H "Authorization: Bearer your_jwt_token" \
  -H "Content-Type: application/json" \
  -d '{
    "alias_email": "support@yourdomain.com",
    "target_email": "admin@yourdomain.com"
  }'
```

### 设置 Webhooks

配置 Resend Webhooks 以跟踪邮件状态：

```
Webhook URL: https://kkmail.yourdomain.com/api/webhooks/resend
Events: email.sent, email.delivered, email.bounced, email.failed
```

## 🛡️ 安全最佳实践

### 1. 强密码策略

- 使用强随机 JWT 密钥（至少 32 位）
- 定期轮换 API 密钥
- 启用双因素认证

### 2. 网络安全

- 配置适当的 CORS 策略
- 启用 HTTPS（Cloudflare 自动提供）
- 监控异常访问

### 3. 数据保护

- 定期备份 D1 数据库
- 实施数据保留政策
- 加密敏感数据

## 📊 监控和维护

### 日志监控

```bash
# 实时查看 Worker 日志
wrangler tail --env production

# 查看数据库统计
wrangler d1 info kkmail-db --env production
```

### 性能监控

- 监控 Worker 执行时间
- 跟踪邮件发送成功率
- 分析数据库查询性能

### 定期维护

- 清理旧邮件数据
- 更新依赖包
- 检查安全漏洞

## 🐛 故障排除

### 常见错误

1. **Worker 部署失败**
   ```bash
   # 检查配置文件
   wrangler validate

   # 检查绑定
   wrangler secret list --env production
   ```

2. **数据库连接错误**
   ```bash
   # 测试数据库连接
   wrangler d1 execute kkmail-db --env production --command="SELECT 1"
   ```

3. **邮件发送失败**
   - 检查 Resend API 密钥
   - 验证域名状态
   - 检查 DNS 配置

4. **邮件接收失败**
   - 确认 MX 记录配置
   - 检查 Email Routing 设置
   - 验证 Worker 路由

### 获取帮助

- [Cloudflare Discord](https://discord.gg/cloudflaredev)
- [Resend 支持](https://resend.com/support)
- [GitHub Issues](https://github.com/stcn52/kkmail/issues)

---

完成以上步骤后，您的 KKMail 服务应该已经完全配置并运行！