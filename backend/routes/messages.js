/**
 * PHANTOM CHAT - Message Routes
 * GET /api/messages/:roomId – Fetch message history for a room
 */

'use strict';

const express = require('express');
const router  = express.Router();

const { Message, Room } = require('../models');
const { decrypt }  = require('../utils/encryption');
const logger = require('../utils/logger');

const requireAuth = (req, res, next) => {
  if (!req.session || !req.session.userId) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  next();
};

// ─── GET /api/messages/:roomId ────────────────────────────────────────────────
router.get('/:roomId', requireAuth, async (req, res) => {
  try {
    const { roomId } = req.params;
    const { before, limit = 50 } = req.query;

    // Verify user is member of room
    const room = await Room.findById(roomId);
    if (!room) return res.status(404).json({ error: 'Room not found' });

    const isMember = room.members.some(m => m.toString() === req.session.userId);
    if (!isMember && room.type !== 'public') {
      return res.status(403).json({ error: 'Not a member of this room' });
    }

    const query = { room: roomId };
    if (before) query.createdAt = { $lt: new Date(before) };

    const messages = await Message.find(query)
      .sort({ createdAt: -1 })
      .limit(Math.min(parseInt(limit), 100))
      .lean();

    // Decrypt server-side layer before returning
    const decrypted = messages.map(msg => {
      try {
        if (msg.iv && msg.authTag) {
          return { ...msg, content: decrypt(msg.content, msg.iv, msg.authTag) };
        }
        return msg;
      } catch {
        return { ...msg, content: '[decryption failed]' };
      }
    });

    res.json({ messages: decrypted.reverse() });

  } catch (err) {
    logger.error('GET /messages/:roomId error:', err.message);
    res.status(500).json({ error: 'Failed to fetch messages' });
  }
});

module.exports = router;
