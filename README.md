# 👁️ PHANTOM CHAT
### Secure · Anonymous · Encrypted · Real-Time Chat

```
 ██████╗ ██╗  ██╗ █████╗ ███╗  ██╗████████╗ ██████╗ ███╗  ███╗
 ██╔══██╗██║  ██║██╔══██╗████╗ ██║╚══██╔══╝██╔═══██╗████╗████║
 ██████╔╝███████║███████║██╔██╗██║   ██║   ██║   ██║██╔████╔██║
 ██╔═══╝ ██╔══██║██╔══██║██║╚████║   ██║   ██║   ██║██║╚██╔╝██║
 ██║     ██║  ██║██║  ██║██║ ╚███║   ██║   ╚██████╔╝██║ ╚═╝ ██║
 ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚══╝  ╚═╝    ╚═════╝ ╚═╝     ╚═╝
```

An educational, privacy-focused anonymous chat system built with Node.js, Socket.io, MongoDB, and vanilla JS with the Web Crypto API.

---

## 🏗️ Project Structure

```
/chat-app
├── backend/
│   ├── server.js              ← Express + Socket.io entry point
│   ├── package.json
│   ├── .env.example           ← Copy to .env and fill values
│   ├── Dockerfile
│   ├── routes/
│   │   ├── auth.js            ← POST /api/auth/register|login|logout
│   │   ├── rooms.js           ← GET/POST/DELETE /api/rooms
│   │   └── messages.js        ← GET /api/messages/:roomId
│   ├── models/
│   │   └── index.js           ← User, Room, Message Mongoose schemas
│   ├── middleware/
│   │   └── errorHandler.js
│   └── utils/
│       ├── encryption.js      ← AES-256-GCM server-side encryption
│       ├── socketHandler.js   ← All real-time WebSocket events
│       └── logger.js          ← Winston logger
├── frontend/
│   └── index.html             ← Complete SPA (HTML + CSS + JS)
├── database/
│   └── mongo-init.js          ← MongoDB initialization script
├── docker/
│   └── nginx.conf             ← Nginx reverse proxy config
├── docker-compose.yml
└── README.md
```

---

## 🔐 Security Architecture

### Layered Encryption (Defense in Depth)

```
User types message
       │
       ▼
[Client E2E Encryption]
  Web Crypto API
  AES-256-GCM
  Key derived from room code
  via PBKDF2 (100k iterations)
       │
       ▼  ← Only ciphertext leaves the browser
[Transport]
  HTTPS/WSS (TLS 1.2/1.3)
       │
       ▼
[Server Re-encryption]
  AES-256-GCM (ENCRYPTION_KEY)
  Stored in MongoDB as double-encrypted
       │
       ▼
[MongoDB Storage]
  Only ciphertext + IV + authTag stored
  TTL index auto-deletes after X hours
```

### Security Features Implemented

| Feature | Implementation |
|---------|---------------|
| E2E Encryption | Web Crypto API, AES-256-GCM, PBKDF2 key derivation |
| Server Encryption | Node.js `crypto`, AES-256-GCM |
| Rate Limiting | `express-rate-limit` (global + per-socket) |
| XSS Protection | `xss` library + CSP headers via `helmet` |
| CSRF Protection | `sameSite: strict` cookies + `helmet` |
| NoSQL Injection | `express-mongo-sanitize` |
| Session Security | `express-session` + MongoDB store, httpOnly cookies |
| Input Validation | `express-validator` on all endpoints |
| Body Size Limit | `10kb` max request body |
| Security Headers | Full `helmet` suite (HSTS, CSP, X-Frame-Options, etc.) |
| Password Hashing | `bcryptjs` with configurable rounds |
| Non-root Docker | Runs as `phantom` user (UID 1001) |
| Timing Attacks | `crypto.timingSafeEqual` for comparisons |

---

## 🚀 Quick Start (Local Development)

### Prerequisites
- Node.js 18+
- MongoDB 6+ (or Docker)

### 1. Clone and Setup

```bash
git clone <your-repo> phantom-chat
cd phantom-chat

# Install backend dependencies
cd backend
npm install

# Copy and configure environment
cp .env.example .env
# Edit .env with your values (see below)
```

### 2. Generate Secret Keys

```bash
# SESSION_SECRET (64 bytes)
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"

# ENCRYPTION_KEY (32 bytes)
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

Paste these into your `.env` file.

### 3. Start MongoDB

```bash
# Option A: Docker
docker run -d -p 27017:27017 --name phantom-mongo mongo:7

# Option B: Local mongod
mongod --dbpath /data/db
```

### 4. Start Backend

```bash
cd backend
npm run dev     # Development (nodemon)
# or
npm start       # Production
```

### 5. Open Frontend

Open `frontend/index.html` directly in a browser, OR access via the server at:
```
http://localhost:3001
```

---

## 🐳 Docker Deployment (Recommended)

### 1. Create `.env` file in project root

```bash
cp backend/.env.example .env
# Fill in SESSION_SECRET and ENCRYPTION_KEY
```

### 2. Start all services

```bash
docker-compose up -d
```

This starts:
- `phantom_mongodb`  — MongoDB on internal network
- `phantom_backend`  — Node.js API + WebSocket server
- `phantom_nginx`    — Nginx reverse proxy on port 80

### 3. View logs

```bash
docker-compose logs -f backend
docker-compose logs -f nginx
```

### 4. Stop

```bash
docker-compose down
# To also remove data volumes:
docker-compose down -v
```

---

## 🖥️ VPS Deployment (Ubuntu 22.04)

### Step 1: Server Setup

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Node.js 20
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs

# Install MongoDB
curl -fsSL https://www.mongodb.org/static/pgp/server-7.0.asc | \
  sudo gpg -o /usr/share/keyrings/mongodb-server-7.0.gpg --dearmor
echo "deb [ arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-7.0.gpg ] \
  https://repo.mongodb.org/apt/ubuntu jammy/mongodb-org/7.0 multiverse" | \
  sudo tee /etc/apt/sources.list.d/mongodb-org-7.0.list
sudo apt update && sudo apt install -y mongodb-org
sudo systemctl enable --now mongod

# Install Nginx
sudo apt install -y nginx

# Install PM2 (process manager)
sudo npm install -g pm2
```

### Step 2: Deploy Application

```bash
# Create app directory
sudo mkdir -p /opt/phantom-chat
sudo chown $USER:$USER /opt/phantom-chat

# Copy files
cp -r backend/ /opt/phantom-chat/
cp -r frontend/ /opt/phantom-chat/

# Install dependencies
cd /opt/phantom-chat/backend
npm install --omit=dev

# Configure environment
cp .env.example .env
nano .env   # Fill in all values, set NODE_ENV=production
```

### Step 3: Start with PM2

```bash
cd /opt/phantom-chat/backend
pm2 start server.js --name phantom-chat
pm2 save
pm2 startup   # Follow the printed command to enable on boot
```

### Step 4: Configure Nginx

```bash
sudo cp /opt/phantom-chat/docker/nginx.conf /etc/nginx/nginx.conf
# Edit: update server_name, frontend root path, and SSL config

sudo nginx -t   # Test config
sudo systemctl restart nginx
```

### Step 5: SSL with Let's Encrypt

```bash
sudo apt install -y certbot python3-certbot-nginx
sudo certbot --nginx -d yourdomain.com

# Auto-renewal (add to crontab)
0 12 * * * certbot renew --quiet
```

### Step 6: Firewall

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
```

---

## 📡 API Reference

### Auth
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/register` | Create anonymous identity |
| POST | `/api/auth/login` | Reclaim identity |
| POST | `/api/auth/logout` | End session |
| GET  | `/api/auth/me` | Get current user |

### Rooms
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET    | `/api/rooms` | List public rooms |
| POST   | `/api/rooms` | Create room |
| GET    | `/api/rooms/:code` | Get room by code |
| DELETE | `/api/rooms/:id` | Delete room |

### Messages
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/messages/:roomId` | Get message history |

### WebSocket Events

**Client → Server**
| Event | Payload | Description |
|-------|---------|-------------|
| `auth` | `{ username }` | Authenticate socket |
| `room:join` | `{ roomCode, password? }` | Join a room |
| `room:leave` | `{ roomId }` | Leave a room |
| `message:send` | `{ roomId, content, iv, authTag, ttlHours }` | Send encrypted message |
| `typing:start` | `{ roomId }` | Start typing |
| `typing:stop` | `{ roomId }` | Stop typing |

**Server → Client**
| Event | Description |
|-------|-------------|
| `room:joined` | Room join success with history + users |
| `room:user_joined` | Another user joined |
| `room:user_left` | User left |
| `message:new` | New message received |
| `typing:update` | Someone is/isn't typing |
| `error` | Error message |

---

## ⚙️ Configuration Reference (`.env`)

| Variable | Required | Description |
|----------|----------|-------------|
| `NODE_ENV` | Yes | `development` or `production` |
| `PORT` | No | Server port (default: 3001) |
| `MONGODB_URI` | Yes | MongoDB connection string |
| `SESSION_SECRET` | **Yes** | 64-byte random hex (change!) |
| `ENCRYPTION_KEY` | **Yes** | 32-byte random hex (change!) |
| `FRONTEND_URL` | Yes | CORS origin for frontend |
| `DEFAULT_MSG_TTL_HOURS` | No | Default message lifetime (24h) |
| `MAX_MSG_TTL_HOURS` | No | Maximum message lifetime (168h) |
| `BCRYPT_ROUNDS` | No | Password hash rounds (default: 12) |

---

## 🛡️ Security Checklist for Production

- [ ] Set strong random `SESSION_SECRET` (64+ bytes)
- [ ] Set strong random `ENCRYPTION_KEY` (32 bytes)
- [ ] Set `NODE_ENV=production`
- [ ] Enable HTTPS (TLS 1.2+) via Let's Encrypt
- [ ] Uncomment HSTS header in nginx.conf
- [ ] Set MongoDB auth (username/password)
- [ ] Enable UFW firewall (only ports 22, 80, 443)
- [ ] Don't expose port 27017 externally
- [ ] Set up log rotation
- [ ] Enable MongoDB automatic backups
- [ ] Monitor with PM2 or systemd
- [ ] Run `npm audit` regularly

---

## 📝 License

MIT — Educational use. Do not use for illegal activities.
