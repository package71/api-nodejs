const defaultConfig = {
  "project_name": "API",
  "shema": "http",
  "domain": "localhost:3010",
  "server_path": "/",
  "api_path": "api/v1/",
  "server": {
    "session": {
      "enable": true,
      "name": "session_key",
      "secret": "session_secret",
      "ttl_hours": 48,
      "driver": "mongodb",
      "database": {
        "username": "",
        "password": "",
        "database": "test",
        "host": "127.0.0.1:27017"
      },
      "cookie": {},
      "saveUninitialized": true,
      "resave": true
    },
    "api": {
      "timeout": 10,
      "debug": {
        "stack": true,
        "log": true,
        "errorResponse": true,
        "successResponse": false
      }
    }
  },
  "redis": {
    "port": 6379,
    "host": "localhost",
    "password": "",
    "database": 0
  },
  "api": {
    "docs": {
      "public": true,
      "user": true,
      "admin": false,
      "server": false
    }
  }
}