# KKMail API 文档

## 认证

所有受保护的 API 端点都需要 JWT 令牌认证。在请求头中包含：

```
Authorization: Bearer your_jwt_token
```

## 端点列表

### 1. 系统管理

#### 初始化数据库
```http
POST /api/init
```

初始化数据库表和默认数据。

**响应：**
```json
{
  "success": true,
  "message": "Database initialized successfully"
}
```

### 2. 认证

#### 用户登录
```http
POST /api/auth/login
Content-Type: application/json
```

**请求体：**
```json
{
  "email": "admin@yourdomain.com",
  "password": "your_password"
}
```

**响应：**
```json
{
  "success": true,
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": 1,
    "email": "admin@yourdomain.com"
  }
}
```

### 3. 邮件发送

#### 发送邮件
```http
POST /api/send
Authorization: Bearer your_jwt_token
Content-Type: application/json
```

**请求体：**
```json
{
  "from": "noreply@yourdomain.com",
  "to": "recipient@example.com",
  "subject": "邮件主题",
  "html": "<h1>HTML 内容</h1>",
  "text": "纯文本内容",
  "cc": ["cc@example.com"],
  "bcc": ["bcc@example.com"],
  "replyTo": "reply@yourdomain.com",
  "attachments": [
    {
      "filename": "document.pdf",
      "content": "base64_encoded_content",
      "type": "application/pdf"
    }
  ]
}
```

**响应：**
```json
{
  "success": true,
  "id": "resend_email_id",
  "data": {
    "id": "resend_email_id",
    "from": "noreply@yourdomain.com",
    "to": ["recipient@example.com"],
    "created_at": "2024-01-01T12:00:00.000Z"
  }
}
```

### 4. 邮件管理

#### 获取邮件列表
```http
GET /api/emails?limit=50&offset=0&status=received
Authorization: Bearer your_jwt_token
```

**查询参数：**
- `limit` (可选): 返回邮件数量，默认 50
- `offset` (可选): 偏移量，默认 0
- `status` (可选): 邮件状态筛选 (received, read, archived, deleted)

**响应：**
```json
{
  "success": true,
  "emails": [
    {
      "id": 1,
      "message_id": "unique_message_id",
      "from_email": "sender@example.com",
      "to_email": "recipient@yourdomain.com",
      "subject": "邮件主题",
      "status": "received",
      "created_at": "2024-01-01T12:00:00.000Z",
      "read_at": null
    }
  ],
  "total": 1
}
```

#### 获取单个邮件详情
```http
GET /api/emails/{emailId}
Authorization: Bearer your_jwt_token
```

**响应：**
```json
{
  "success": true,
  "email": {
    "id": 1,
    "message_id": "unique_message_id",
    "from_email": "sender@example.com",
    "to_email": "recipient@yourdomain.com",
    "cc_emails": "cc@example.com",
    "bcc_emails": null,
    "subject": "邮件主题",
    "body_text": "邮件纯文本内容",
    "body_html": "<h1>邮件HTML内容</h1>",
    "headers": "{\"x-header\": \"value\"}",
    "attachments": "[]",
    "status": "received",
    "created_at": "2024-01-01T12:00:00.000Z",
    "read_at": null
  }
}
```

#### 标记邮件为已读
```http
PUT /api/emails/{messageId}/read
Authorization: Bearer your_jwt_token
```

**响应：**
```json
{
  "success": true,
  "message": "Email marked as read"
}
```

#### 删除邮件
```http
DELETE /api/emails/{messageId}
Authorization: Bearer your_jwt_token
```

**响应：**
```json
{
  "success": true,
  "message": "Email deleted"
}
```

### 5. 邮件别名管理

#### 创建邮件别名
```http
POST /api/aliases
Authorization: Bearer your_jwt_token
Content-Type: application/json
```

**请求体：**
```json
{
  "alias_email": "support@yourdomain.com",
  "target_email": "admin@yourdomain.com"
}
```

**响应：**
```json
{
  "success": true,
  "message": "Alias created successfully"
}
```

#### 获取邮件别名列表
```http
GET /api/aliases
Authorization: Bearer your_jwt_token
```

**响应：**
```json
{
  "success": true,
  "aliases": [
    {
      "alias_email": "support@yourdomain.com",
      "target_email": "admin@yourdomain.com",
      "created_at": "2024-01-01T12:00:00.000Z"
    }
  ]
}
```

#### 删除邮件别名
```http
DELETE /api/aliases/{aliasEmail}
Authorization: Bearer your_jwt_token
```

**响应：**
```json
{
  "success": true,
  "message": "Alias removed successfully"
}
```

### 6. 发送日志

#### 获取发送日志
```http
GET /api/send-logs?limit=50&offset=0
Authorization: Bearer your_jwt_token
```

**响应：**
```json
{
  "success": true,
  "logs": [
    {
      "id": 1,
      "from_email": "noreply@yourdomain.com",
      "to_email": "recipient@example.com",
      "subject": "邮件主题",
      "status": "sent",
      "resend_id": "resend_email_id",
      "error_message": null,
      "created_at": "2024-01-01T12:00:00.000Z"
    }
  ]
}
```

### 7. Webhooks

#### Resend Webhook 处理
```http
POST /api/webhooks/resend
Content-Type: application/json
```

用于接收 Resend 的邮件状态更新。

**请求体示例：**
```json
{
  "type": "email.delivered",
  "created_at": "2024-01-01T12:00:00.000Z",
  "data": {
    "email_id": "resend_email_id",
    "from": "noreply@yourdomain.com",
    "to": ["recipient@example.com"],
    "subject": "邮件主题"
  }
}
```

## 错误处理

所有 API 端点在出错时返回统一的错误格式：

```json
{
  "error": "错误类型",
  "message": "详细错误信息"
}
```

### 常见 HTTP 状态码

- `200` - 成功
- `400` - 请求参数错误
- `401` - 认证失败
- `403` - 权限不足
- `404` - 资源不存在
- `500` - 服务器内部错误

### 常见错误类型

1. **认证错误**
   ```json
   {
     "error": "Authorization required",
     "message": "Missing or invalid authorization header"
   }
   ```

2. **令牌错误**
   ```json
   {
     "error": "Invalid token",
     "message": "JWT signature verification failed"
   }
   ```

3. **参数错误**
   ```json
   {
     "error": "Validation error",
     "message": "Missing required field: to"
   }
   ```

4. **邮件发送错误**
   ```json
   {
     "error": "Email send failed",
     "message": "Resend API error: Invalid from address"
   }
   ```

## 使用示例

### JavaScript (Fetch API)

```javascript
// 登录获取令牌
const loginResponse = await fetch('https://kkmail.yourdomain.com/api/auth/login', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({
    email: 'admin@yourdomain.com',
    password: 'your_password'
  })
});

const loginData = await loginResponse.json();
const token = loginData.token;

// 发送邮件
const sendResponse = await fetch('https://kkmail.yourdomain.com/api/send', {
  method: 'POST',
  headers: {
    'Authorization': `Bearer ${token}`,
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({
    from: 'noreply@yourdomain.com',
    to: 'recipient@example.com',
    subject: '测试邮件',
    text: '这是一封测试邮件'
  })
});

const sendData = await sendResponse.json();
console.log(sendData);
```

### Python (requests)

```python
import requests

# 登录
login_data = {
    'email': 'admin@yourdomain.com',
    'password': 'your_password'
}

response = requests.post(
    'https://kkmail.yourdomain.com/api/auth/login',
    json=login_data
)

token = response.json()['token']

# 发送邮件
headers = {
    'Authorization': f'Bearer {token}',
    'Content-Type': 'application/json'
}

email_data = {
    'from': 'noreply@yourdomain.com',
    'to': 'recipient@example.com',
    'subject': '测试邮件',
    'text': '这是一封测试邮件'
}

response = requests.post(
    'https://kkmail.yourdomain.com/api/send',
    headers=headers,
    json=email_data
)

print(response.json())
```

### cURL

```bash
# 登录
TOKEN=$(curl -s -X POST "https://kkmail.yourdomain.com/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@yourdomain.com","password":"your_password"}' \
  | jq -r '.token')

# 发送邮件
curl -X POST "https://kkmail.yourdomain.com/api/send" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "from": "noreply@yourdomain.com",
    "to": "recipient@example.com",
    "subject": "测试邮件",
    "text": "这是一封测试邮件"
  }'
```

## 速率限制

为防止滥用，API 实施以下速率限制：

- **发送邮件**: 每分钟最多 100 次请求
- **其他 API**: 每分钟最多 1000 次请求

超出限制时返回 `429 Too Many Requests` 状态码。

## 版本控制

当前 API 版本: `v1`

所有端点都包含在 `/api/` 路径下。未来版本将使用 `/api/v2/` 等路径。