# API Documentation

## Authentication

### Basic Authentication
All API endpoints require basic authentication.

```
Authorization: Basic <base64-encoded-credentials>
```

Default credentials:
- Username: admin
- Password: 123

Failed authentication will return a 401 Unauthorized response.

## Endpoints

### Configuration Management

#### 1. Get Current Configuration
```http
GET /api/config
```

**Response:**
```json
{
    "status": "success",
    "config": {
        "GENERAL_SETTINGS": { ... },
        "IP_RULES": { ... },
        "PORT_RULES": { ... },
        "DNS_RULES": { ... }
    }
}
```

#### 2. Update Configuration
```http
POST /api/config
Content-Type: application/json

{
    "GENERAL_SETTINGS": { ... },
    "IP_RULES": { ... }
}
```

**Response:**
```json
{
    "status": "success",
    "message": "Configuration updated successfully"
}
```

#### 3. Update Configuration Section
```http
PUT /api/config/<section>
Content-Type: application/json

{
    "setting_key": "value"
}
```

**Parameters:**
- section: GENERAL_SETTINGS, IP_RULES, PORT_RULES, or DNS_RULES

### Log Management

#### 1. Get Today's Logs
```http
GET /api/logs/today
```

**Response:**
```json
{
    "status": "success",
    "logs": [
        {
            "timestamp": "2023-12-20 10:15:30",
            "type": "ALERT",
            "message": "Port scan detected",
            "details": { ... }
        },
        ...
    ]
}
```

#### 2. Download Logs
```http
GET /api/logs/download
```

**Response:**
- Content-Type: text/plain
- File download of today's logs

#### 3. Get Available Log Dates
```http
GET /api/logs/dates
```

**Response:**
```json
{
    "status": "success",
    "dates": [
        "2023-12-20",
        "2023-12-19",
        ...
    ]
}
```

#### 4. Get Logs for Specific Date
```http
GET /api/logs/date/<date>
```

**Parameters:**
- date: Date in YYYY-MM-DD format

### Real-time Events

#### Event Stream
```http
GET /events
```

**Response:**
Server-Sent Events (SSE) stream with the following event types:
1. packet_stats
2. alerts
3. connections
4. dns_queries

Example event:
```
event: packet_stats
data: {
    "total_packets": 1500,
    "packets_per_second": 25,
    "active_connections": 10
}
```

## Error Handling

### Error Response Format
```json
{
    "status": "error",
    "error": "Error message",
    "code": "ERROR_CODE"
}
```

### Common Error Codes
- `AUTH_FAILED`: Authentication failed
- `INVALID_CONFIG`: Invalid configuration data
- `CONFIG_UPDATE_FAILED`: Failed to update configuration
- `LOG_NOT_FOUND`: Requested log not found
- `INVALID_DATE`: Invalid date format
- `INTERNAL_ERROR`: Internal server error

### HTTP Status Codes
- 200: Success
- 400: Bad Request
- 401: Unauthorized
- 404: Not Found
- 500: Internal Server Error

## Rate Limiting

- Maximum 100 requests per minute per IP
- Rate limit headers included in response:
  ```
  X-RateLimit-Limit: 100
  X-RateLimit-Remaining: 95
  X-RateLimit-Reset: 1608481380
  ```

## Best Practices

1. **Authentication**
   - Store credentials securely
   - Rotate passwords regularly
   - Use HTTPS in production

2. **Configuration Updates**
   - Validate configuration before applying
   - Keep backup of working configuration
   - Test changes in development first

3. **Log Management**
   - Regularly download and archive logs
   - Monitor disk space usage
   - Implement log rotation

4. **Event Streaming**
   - Implement reconnection logic
   - Handle connection timeouts
   - Process events asynchronously
