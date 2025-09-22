# 临时邮箱功能测试指南

## 部署和测试

### 1. 数据库初始化

首先需要运行数据库迁移来创建临时邮箱所需的表：

```bash
# 运行数据库迁移
wrangler d1 execute kkmail-db --file=migrations/001_add_temp_emails.sql

# 或者通过API初始化（需要先部署）
curl -X POST https://your-domain.com/api/init \
  -H "Content-Type: application/json" \
  -d '{"adminEmail": "admin@yourdomain.com"}'
```

### 2. 部署到Cloudflare Workers

```bash
# 部署服务
wrangler deploy

# 检查部署状态
wrangler tail
```

### 3. 功能测试

#### 3.1 创建通用临时邮箱

```bash
curl -X POST https://your-domain.com/api/temp-email/create \
  -H "Content-Type: application/json" \
  -d '{
    "expiryHours": 24,
    "purpose": "general",
    "maxEmails": 50
  }'
```

预期响应：
```json
{
  "success": true,
  "email": "temp-abc123-xyz789@yourdomain.com",
  "accessToken": "temp_randomtoken123456",
  "expiresAt": "2024-01-01T12:00:00.000Z",
  "purpose": "general",
  "maxEmails": 50
}
```

#### 3.2 创建注册验证邮箱

```bash
curl -X POST https://your-domain.com/api/temp-email/create-signup \
  -H "Content-Type: application/json" \
  -d '{
    "serviceName": "GitHub"
  }'
```

#### 3.3 创建邮箱验证邮箱

```bash
curl -X POST https://your-domain.com/api/temp-email/create-verification \
  -H "Content-Type: application/json" \
  -d '{
    "verificationType": "email"
  }'
```

#### 3.4 查看临时邮箱收到的邮件

```bash
curl "https://your-domain.com/api/temp-email/temp-abc123-xyz789@yourdomain.com/emails?token=temp_randomtoken123456"
```

#### 3.5 延长邮箱时间

```bash
curl -X POST https://your-domain.com/api/temp-email/temp-abc123-xyz789@yourdomain.com/extend \
  -H "Content-Type: application/json" \
  -d '{
    "accessToken": "temp_randomtoken123456",
    "additionalHours": 12
  }'
```

#### 3.6 查看邮箱统计

```bash
curl "https://your-domain.com/api/temp-email/temp-abc123-xyz789@yourdomain.com/stats?token=temp_randomtoken123456"
```

#### 3.7 标记邮件为已读

```bash
curl -X POST https://your-domain.com/api/temp-email/temp-abc123-xyz789@yourdomain.com/mark-read \
  -H "Content-Type: application/json" \
  -d '{
    "accessToken": "temp_randomtoken123456",
    "messageId": "kkmail-123456789-0.123"
  }'
```

#### 3.8 删除邮件

```bash
curl -X POST https://your-domain.com/api/temp-email/temp-abc123-xyz789@yourdomain.com/delete-email \
  -H "Content-Type: application/json" \
  -d '{
    "accessToken": "temp_randomtoken123456",
    "messageId": "kkmail-123456789-0.123"
  }'
```

### 4. 管理员功能测试

#### 4.1 获取管理员令牌

```bash
curl -X POST https://your-domain.com/api/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@yourdomain.com",
    "password": "your-admin-password"
  }'
```

#### 4.2 查看所有临时邮箱

```bash
curl "https://your-domain.com/api/temp-email/admin/all" \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN"
```

#### 4.3 查看临时邮箱统计

```bash
curl "https://your-domain.com/api/temp-email/admin/stats" \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN"
```

#### 4.4 清理过期邮箱

```bash
curl -X POST https://your-domain.com/api/temp-email/admin/cleanup \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN"
```

### 5. 前端界面测试

#### 5.1 管理界面
访问 `https://your-domain.com/admin` 登录管理界面，测试：
- 仪表板是否显示临时邮箱统计
- 临时邮箱标签页是否正常工作
- 创建临时邮箱功能
- 查看器功能

#### 5.2 公共临时邮箱界面
访问 `https://your-domain.com/temp-email` 测试：
- 创建临时邮箱
- 查看邮件
- 复制功能
- 倒计时显示
- 延长时间功能

### 6. 邮件接收测试

1. 创建一个临时邮箱
2. 向该邮箱发送测试邮件
3. 检查邮件是否正确接收和存储
4. 验证临时邮箱标记是否正确

可以使用以下服务发送测试邮件：
- Gmail
- Outlook
- 其他邮件服务

### 7. 自动化测试脚本

创建一个简单的测试脚本：

```javascript
// test-temp-email.js
const API_BASE = 'https://your-domain.com/api';

async function runTests() {
    console.log('开始临时邮箱功能测试...');

    // 测试1: 创建临时邮箱
    console.log('测试1: 创建通用临时邮箱');
    const createResponse = await fetch(`${API_BASE}/temp-email/create`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            expiryHours: 1,
            purpose: 'general',
            maxEmails: 10
        })
    });

    const tempEmail = await createResponse.json();
    console.log('创建结果:', tempEmail);

    if (!tempEmail.success) {
        console.error('创建失败:', tempEmail.error);
        return;
    }

    // 测试2: 获取邮件列表
    console.log('测试2: 获取邮件列表');
    const emailsResponse = await fetch(
        `${API_BASE}/temp-email/${encodeURIComponent(tempEmail.email)}/emails?token=${encodeURIComponent(tempEmail.accessToken)}`
    );

    const emails = await emailsResponse.json();
    console.log('邮件列表:', emails);

    // 测试3: 获取统计信息
    console.log('测试3: 获取统计信息');
    const statsResponse = await fetch(
        `${API_BASE}/temp-email/${encodeURIComponent(tempEmail.email)}/stats?token=${encodeURIComponent(tempEmail.accessToken)}`
    );

    const stats = await statsResponse.json();
    console.log('统计信息:', stats);

    // 测试4: 延长时间
    console.log('测试4: 延长时间');
    const extendResponse = await fetch(
        `${API_BASE}/temp-email/${encodeURIComponent(tempEmail.email)}/extend`,
        {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                accessToken: tempEmail.accessToken,
                additionalHours: 1
            })
        }
    );

    const extendResult = await extendResponse.json();
    console.log('延长时间结果:', extendResult);

    console.log('测试完成！');
    console.log('临时邮箱地址:', tempEmail.email);
    console.log('访问令牌:', tempEmail.accessToken);
    console.log('请手动向此邮箱发送测试邮件并验证接收功能');
}

// 在浏览器控制台中运行
runTests().catch(console.error);
```

### 8. 故障排除

#### 8.1 常见问题

1. **数据库连接失败**
   - 检查 wrangler.toml 中的数据库配置
   - 确认数据库已正确创建

2. **邮件接收失败**
   - 检查 Cloudflare Email Routing 设置
   - 验证域名 DNS 配置

3. **API 访问被拒绝**
   - 检查 CORS 设置
   - 验证访问令牌有效性

4. **过期时间计算错误**
   - 检查时区设置
   - 验证日期时间格式

#### 8.2 调试日志

在 Cloudflare Workers 中查看实时日志：

```bash
wrangler tail
```

### 9. 性能测试

#### 9.1 并发创建测试

```bash
# 创建100个并发请求
for i in {1..100}; do
  curl -X POST https://your-domain.com/api/temp-email/create \
    -H "Content-Type: application/json" \
    -d '{"expiryHours": 1, "purpose": "general", "maxEmails": 10}' &
done
wait
```

#### 9.2 邮件处理性能

测试大量邮件同时到达时的处理性能。

### 10. 安全测试

1. **访问令牌安全性**
   - 尝试使用无效令牌访问
   - 测试令牌猜测攻击

2. **输入验证**
   - 测试 SQL 注入
   - 测试 XSS 攻击

3. **速率限制**
   - 测试频繁创建邮箱
   - 验证防止滥用机制

## 预期结果

所有测试应该通过，功能应该：
- 正确创建临时邮箱
- 准确接收和存储邮件
- 正确处理过期逻辑
- 安全地管理访问权限
- 提供良好的用户体验

如果发现任何问题，请检查代码实现和配置设置。