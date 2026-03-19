'use strict';

require('dotenv').config();

const express      = require('express');
const http         = require('http');
const { Server }   = require('socket.io');
const mongoose     = require('mongoose');
const session      = require('express-session');
const MongoStore   = require('connect-mongo');
const helmet       = require('helmet');
const cors         = require('cors');
const compression  = require('compression');
const morgan       = require('morgan');
const rateLimit    = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');
const cookieParser = require('cookie-parser');
const path         = require('path');

const logger        = require('./utils/logger');
const socketHandler = require('./utils/socketHandler');
const authRoutes    = require('./routes/auth');
const roomRoutes    = require('./routes/rooms');
const messageRoutes = require('./routes/messages');
const { errorHandler } = require('./middleware/errorHandler');

const app    = express();
const server = http.createServer(app);

// CRITICAL: trust nginx proxy
app.set('trust proxy', 1);

mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/phantomchat')
.then(() => logger.info('✓ MongoDB connected'))
.catch(err => {
  logger.error('✗ MongoDB connection failed:', err.message);
  process.exit(1);
});

const sessionMiddleware = session({
  secret:            process.env.SESSION_SECRET || 'fallback-secret-change-me',
  resave:            true,
  saveUninitialized: true,   // ← CHANGED: save session immediately
  store: MongoStore.create({
    mongoUrl:   process.env.MONGODB_URI || 'mongodb://localhost:27017/phantomchat',
    ttl:        24 * 60 * 60,
    autoRemove: 'native',
  }),
  cookie: {
    secure:   false,   // ← false for HTTP
    httpOnly: true,
    sameSite: 'lax',   // ← lax works through nginx proxy
    maxAge:   24 * 60 * 60 * 1000,
    path:     '/',
    domain:   undefined,  // let browser handle domain
  },
  name: 'phantom.sid',  // ← simpler name, no underscore prefix
});

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc:  ["'self'", "'unsafe-inline'", "https://cdn.socket.io"],
      styleSrc:   ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc:    ["'self'", "https://fonts.gstatic.com"],
      connectSrc: ["'self'", "ws:", "wss:"],
      imgSrc:     ["'self'", "data:"],
      objectSrc:  ["'none'"],
    },
  },
  hsts: false,  // ← disable HSTS since we're on HTTP
}));

const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max:      200,
  standardHeaders: true,
  legacyHeaders:   false,
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max:      50,
});

app.use(globalLimiter);
app.use(compression());
app.use(morgan('dev'));
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(cookieParser());
app.use(mongoSanitize());

// CORS - must be before session
app.use(cors({
  origin:      true,   // ← reflect request origin (works for localhost)
  credentials: true,   // ← CRITICAL: allow cookies
  methods:     ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Cookie'],
}));

// Session - must be after cors
app.use(sessionMiddleware);

// Debug middleware - remove after fixing
app.use((req, res, next) => {
  logger.info(`${req.method} ${req.path} | sessionID: ${req.sessionID} | userId: ${req.session?.userId || 'none'}`);
  next();
});

app.use(express.static(path.join(__dirname, '../frontend')));

app.use('/api/auth',     authLimiter, authRoutes);
app.use('/api/rooms',    roomRoutes);
app.use('/api/messages', messageRoutes);

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', uptime: process.uptime() });
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/index.html'));
});

app.use(errorHandler);

const io = new Server(server, {
  cors: {
    origin:      true,
    credentials: true,
    methods:     ['GET', 'POST'],
  },
  pingTimeout:  60000,
  pingInterval: 25000,
});

io.use((socket, next) => {
  sessionMiddleware(socket.request, {}, next);
});

socketHandler(io);

const PORT = process.env.PORT || 3001;
server.listen(PORT, () => {
  logger.info(`✓ Phantom Chat running on port ${PORT}`);
});

process.on('SIGTERM', () => {
  server.close(() => {
    mongoose.connection.close();
    process.exit(0);
  });
});

module.exports = { app, server, io };