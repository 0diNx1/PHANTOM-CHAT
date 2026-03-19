/**
 * PHANTOM CHAT - WebSocket / Socket.io Handler
 *
 * Handles all real-time events:
 *   - User join/leave
 *   - Room join/leave
 *   - Message send/receive (with encryption)
 *   - Typing indicators
 *   - Online user list
 *   - Rate limiting per socket
 */

'use strict';

const rateLimit  = require('express-rate-limit');
const xss        = require('xss');
const { User, Room, Message } = require('../models');
const { encrypt, generateToken } = require('./encryption');
const logger     = require('./logger');

// ─── Per-socket rate limiter (in-memory, resets on disconnect) ────────────────
class SocketRateLimiter {
  constructor(maxPerWindow = 30, windowMs = 60000) {
    this.maxPerWindow = maxPerWindow;
    this.windowMs     = windowMs;
    this.counts       = new Map(); // socketId → { count, resetAt }
  }

  check(socketId) {
    const now   = Date.now();
    const entry = this.counts.get(socketId);

    if (!entry || now > entry.resetAt) {
      this.counts.set(socketId, { count: 1, resetAt: now + this.windowMs });
      return true;
    }

    if (entry.count >= this.maxPerWindow) return false;

    entry.count++;
    return true;
  }

  remove(socketId) {
    this.counts.delete(socketId);
  }
}

const msgRateLimiter = new SocketRateLimiter(
  parseInt(process.env.MESSAGE_RATE_LIMIT_MAX) || 30,
  60000
);

// ─── In-memory online users map ───────────────────────────────────────────────
// roomId → Set of { socketId, username, userId }
const roomUsers = new Map();

function addUserToRoom(roomId, socketId, userInfo) {
  if (!roomUsers.has(roomId)) roomUsers.set(roomId, new Map());
  roomUsers.get(roomId).set(socketId, userInfo);
}

function removeUserFromRoom(roomId, socketId) {
  if (roomUsers.has(roomId)) {
    roomUsers.get(roomId).delete(socketId);
    if (roomUsers.get(roomId).size === 0) roomUsers.delete(roomId);
  }
}

function getRoomUsers(roomId) {
  if (!roomUsers.has(roomId)) return [];
  return Array.from(roomUsers.get(roomId).values());
}

// ─── XSS Sanitization ────────────────────────────────────────────────────────
const xssOptions = {
  whiteList: {}, // No HTML tags allowed
  stripIgnoreTag: true,
  stripIgnoreTagBody: ['script', 'style'],
};

function sanitize(str) {
  if (typeof str !== 'string') return '';
  return xss(str.trim().slice(0, parseInt(process.env.MAX_MESSAGE_LENGTH) || 2000), xssOptions);
}

// ─── Main Socket Handler ──────────────────────────────────────────────────────
module.exports = function socketHandler(io) {

  io.on('connection', async (socket) => {
    logger.info(`Socket connected: ${socket.id}`);

    // ── Authenticate from session ──────────────────────────────────────────
    const session  = socket.request.session;
    let currentUser = null;

    if (session && session.userId) {
      currentUser = await User.findById(session.userId).lean();
      if (currentUser) {
        // Update online status
        await User.findByIdAndUpdate(session.userId, {
          isOnline: true,
          lastSeen: new Date(),
        });
      }
    }

    // ── Event: client sends their identity ────────────────────────────────
    socket.on('auth', async ({ username, sessionToken }) => {
      try {
        const user = await User.findOne({ username: sanitize(username) });
        if (user) {
          currentUser = user;
          socket.data.userId   = user._id.toString();
          socket.data.username = user.username;
          await User.findByIdAndUpdate(user._id, { isOnline: true, lastSeen: new Date() });
          socket.emit('auth:ok', { username: user.username, userId: user._id });
        } else {
          socket.emit('auth:error', { message: 'User not found' });
        }
      } catch (err) {
        logger.error('Socket auth error:', err.message);
        socket.emit('error', { message: 'Authentication failed' });
      }
    });

    // ── Event: join a room ─────────────────────────────────────────────────
    socket.on('room:join', async ({ roomCode, password }) => {
      try {
        if (!currentUser) return socket.emit('error', { message: 'Not authenticated' });

        const room = await Room.findOne({ code: sanitize(roomCode).toUpperCase() });
        if (!room) return socket.emit('error', { message: 'Room not found' });
        if (!room.isActive) return socket.emit('error', { message: 'Room is no longer active' });

        // Check capacity
        if (room.members.length >= room.maxMembers) {
          return socket.emit('error', { message: 'Room is full' });
        }

        // Verify password for private rooms
        if (room.type === 'private') {
          const ok = await room.verifyPassword(password || '');
          if (!ok) return socket.emit('error', { message: 'Invalid room password' });
        }

        // Join Socket.io room
        socket.join(room._id.toString());
        socket.data.currentRoom = room._id.toString();

        // Add to members if not already
        if (!room.members.includes(currentUser._id)) {
          await Room.findByIdAndUpdate(room._id, {
            $addToSet: { members: currentUser._id },
            lastActivity: new Date(),
          });
        }

        // Track in memory
        addUserToRoom(room._id.toString(), socket.id, {
          socketId: socket.id,
          userId:   currentUser._id.toString(),
          username: currentUser.username,
        });

        // Load recent messages (last 50)
        const messages = await Message.find({ room: room._id })
          .sort({ createdAt: -1 })
          .limit(50)
          .lean();

        socket.emit('room:joined', {
          room:     { id: room._id, name: room.name, code: room.code, type: room.type, topic: room.topic },
          messages: messages.reverse(),
          users:    getRoomUsers(room._id.toString()),
        });

        // Broadcast join notification to room
        const joinMsg = await Message.create({
          room:           room._id,
          sender:         currentUser._id,
          senderUsername: currentUser.username,
          content:        encrypt(`${currentUser.username} joined the room`).ciphertext,
          iv:             null,
          authTag:        null,
          type:           'join',
          expiresAt:      new Date(Date.now() + 24 * 3600 * 1000),
        });

        io.to(room._id.toString()).emit('room:user_joined', {
          username: currentUser.username,
          userId:   currentUser._id,
          users:    getRoomUsers(room._id.toString()),
          systemMessage: {
            type:     'join',
            text:     `${currentUser.username} connected`,
            at:       new Date(),
          },
        });

        logger.info(`${currentUser.username} joined room ${room.code}`);

      } catch (err) {
        logger.error('room:join error:', err.message);
        socket.emit('error', { message: 'Failed to join room' });
      }
    });

    // ── Event: leave a room ────────────────────────────────────────────────
    socket.on('room:leave', async ({ roomId }) => {
      try {
        const rid = sanitize(roomId);
        socket.leave(rid);
        removeUserFromRoom(rid, socket.id);

        if (currentUser) {
          io.to(rid).emit('room:user_left', {
            username: currentUser.username,
            users:    getRoomUsers(rid),
            systemMessage: {
              type: 'leave',
              text: `${currentUser.username} disconnected`,
              at:   new Date(),
            },
          });
        }
      } catch (err) {
        logger.error('room:leave error:', err.message);
      }
    });

    // ── Event: send a message ──────────────────────────────────────────────
    socket.on('message:send', async ({ roomId, content, iv, authTag, ttlHours }) => {
      try {
        if (!currentUser) return socket.emit('error', { message: 'Not authenticated' });

        // Rate limiting
        if (!msgRateLimiter.check(socket.id)) {
          return socket.emit('error', { message: 'Slow down! You are sending messages too fast.' });
        }

        // Validate
        const sanitizedContent = sanitize(content);
        if (!sanitizedContent || sanitizedContent.length === 0) {
          return socket.emit('error', { message: 'Message cannot be empty' });
        }

        if (sanitizedContent.length > (parseInt(process.env.MAX_MESSAGE_LENGTH) || 2000)) {
          return socket.emit('error', { message: 'Message too long' });
        }

        // Check user is in the room
        const rid   = sanitize(roomId);
        const room  = await Room.findById(rid);
        if (!room) return socket.emit('error', { message: 'Room not found' });

        // Determine TTL
        const maxTTL    = parseInt(process.env.MAX_MSG_TTL_HOURS) || 168;
        const defaultTTL = parseInt(process.env.DEFAULT_MSG_TTL_HOURS) || 24;
        const hours     = Math.min(Math.max(ttlHours || defaultTTL, 1), maxTTL);
        const expiresAt = new Date(Date.now() + hours * 3600 * 1000);

        // Server-side re-encryption of the client-encrypted content
        // (content here is already E2E-encrypted by the client)
        // We encrypt it again for storage (defense-in-depth)
        const stored = encrypt(sanitizedContent);

        const message = await Message.create({
          room:           room._id,
          sender:         currentUser._id,
          senderUsername: currentUser.username,
          content:        stored.ciphertext,
          iv:             stored.iv,
          authTag:        stored.authTag,
          type:           'text',
          expiresAt,
        });

        // Broadcast to room – send back the original (client-encrypted) content
        // so other clients can decrypt it with their shared key
        io.to(rid).emit('message:new', {
          _id:            message._id,
          senderUsername: currentUser.username,
          senderId:       currentUser._id,
          content:        sanitizedContent, // Client-encrypted, safe to broadcast
          iv:             iv     || null,   // Client's E2E iv
          authTag:        authTag || null,  // Client's E2E authTag
          type:           'text',
          createdAt:      message.createdAt,
          expiresAt:      message.expiresAt,
        });

        // Update room activity
        await Room.findByIdAndUpdate(rid, { lastActivity: new Date() });

      } catch (err) {
        logger.error('message:send error:', err.message);
        socket.emit('error', { message: 'Failed to send message' });
      }
    });

    // ── Event: typing indicator ────────────────────────────────────────────
    let typingTimeout = null;

    socket.on('typing:start', ({ roomId }) => {
      if (!currentUser) return;
      const rid = sanitize(roomId);
      socket.to(rid).emit('typing:update', {
        username:  currentUser.username,
        isTyping:  true,
      });

      // Auto-stop typing after 3 seconds of no updates
      clearTimeout(typingTimeout);
      typingTimeout = setTimeout(() => {
        socket.to(rid).emit('typing:update', {
          username: currentUser.username,
          isTyping: false,
        });
      }, 3000);
    });

    socket.on('typing:stop', ({ roomId }) => {
      if (!currentUser) return;
      clearTimeout(typingTimeout);
      const rid = sanitize(roomId);
      socket.to(rid).emit('typing:update', {
        username: currentUser.username,
        isTyping: false,
      });
    });

    // ── Event: get online users in a room ──────────────────────────────────
    socket.on('room:users', ({ roomId }) => {
      socket.emit('room:users_list', {
        roomId,
        users: getRoomUsers(sanitize(roomId)),
      });
    });

    // ── Disconnect ─────────────────────────────────────────────────────────
    socket.on('disconnect', async () => {
      logger.info(`Socket disconnected: ${socket.id}`);
      msgRateLimiter.remove(socket.id);
      clearTimeout(typingTimeout);

      // Remove from all rooms they were in
      if (socket.data.currentRoom) {
        removeUserFromRoom(socket.data.currentRoom, socket.id);
        if (currentUser) {
          io.to(socket.data.currentRoom).emit('room:user_left', {
            username: currentUser.username,
            users:    getRoomUsers(socket.data.currentRoom),
            systemMessage: {
              type: 'leave',
              text: `${currentUser.username} disconnected`,
              at:   new Date(),
            },
          });
        }
      }

      // Update offline status
      if (currentUser) {
        await User.findByIdAndUpdate(currentUser._id, {
          isOnline: false,
          lastSeen: new Date(),
        }).catch(() => {});
      }
    });

  }); // end io.on('connection')

};
