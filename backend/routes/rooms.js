/**
 * PHANTOM CHAT - Room Routes
 * GET    /api/rooms         – List public rooms
 * POST   /api/rooms         – Create a room
 * GET    /api/rooms/:code   – Get room info by code
 * DELETE /api/rooms/:id     – Delete room (creator only)
 */

'use strict';

const express = require('express');
const { body, validationResult } = require('express-validator');
const router  = express.Router();

const { Room, User } = require('../models');
const { generateRoomCode } = require('../utils/encryption');
const logger = require('../utils/logger');

// ─── Auth middleware ──────────────────────────────────────────────────────────
const requireAuth = (req, res, next) => {
  if (!req.session || !req.session.userId) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  next();
};

// ─── GET /api/rooms ───────────────────────────────────────────────────────────
router.get('/', async (req, res) => {
  try {
    const rooms = await Room.find({ type: 'public', isActive: true })
      .select('name code type topic members maxMembers lastActivity createdAt')
      .sort({ lastActivity: -1 })
      .limit(50)
      .lean();

    // Add online member count
    const enriched = rooms.map(r => ({
      ...r,
      memberCount: r.members.length,
    }));

    res.json({ rooms: enriched });
  } catch (err) {
    logger.error('GET /rooms error:', err.message);
    res.status(500).json({ error: 'Failed to fetch rooms' });
  }
});

// ─── POST /api/rooms ──────────────────────────────────────────────────────────
router.post('/',
  requireAuth,
  [
    body('name').trim().isLength({ min: 1, max: 50 }).withMessage('Room name required (max 50 chars)'),
    body('type').isIn(['public', 'private']).withMessage('Type must be public or private'),
    body('topic').optional().trim().isLength({ max: 200 }),
    body('autoDeleteHours').optional().isInt({ min: 0, max: 168 }),
    body('maxMembers').optional().isInt({ min: 2, max: 100 }),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    try {
      const { name, type, topic, password, autoDeleteHours, maxMembers } = req.body;
      const userId = req.session.userId;

      // Limit rooms per user
      const userRoomCount = await Room.countDocuments({ creator: userId, isActive: true });
      if (userRoomCount >= (parseInt(process.env.MAX_ROOMS_PER_USER) || 5)) {
        return res.status(429).json({ error: 'You have reached the maximum number of active rooms' });
      }

      // Generate unique room code with collision check
      let code;
      let attempts = 0;
      do {
        code = generateRoomCode();
        attempts++;
        if (attempts > 10) throw new Error('Failed to generate unique room code');
      } while (await Room.findOne({ code }));

      const room = new Room({
        name,
        code,
        type,
        topic:           topic || '',
        creator:         userId,
        members:         [userId],
        maxMembers:      maxMembers || 50,
        autoDeleteHours: autoDeleteHours || 0,
        passwordHash:    (type === 'private' && password) ? password : null,
      });

      await room.save();

      // Add room to user's list
      await User.findByIdAndUpdate(userId, { $addToSet: { rooms: room._id } });

      logger.info(`Room created: ${name} (${code}) by ${userId}`);

      res.status(201).json({
        message: 'Room created',
        room: {
          id:   room._id,
          name: room.name,
          code: room.code,
          type: room.type,
        },
      });

    } catch (err) {
      logger.error('POST /rooms error:', err.message);
      res.status(500).json({ error: 'Failed to create room' });
    }
  }
);

// ─── GET /api/rooms/:code ─────────────────────────────────────────────────────
router.get('/:code', async (req, res) => {
  try {
    const code = req.params.code.toUpperCase().trim();
    const room = await Room.findOne({ code, isActive: true })
      .select('-passwordHash')
      .lean();

    if (!room) return res.status(404).json({ error: 'Room not found' });

    res.json({
      room: {
        ...room,
        memberCount:   room.members.length,
        hasPassword:   !!room.passwordHash,
      },
    });
  } catch (err) {
    logger.error('GET /rooms/:code error:', err.message);
    res.status(500).json({ error: 'Failed to fetch room' });
  }
});

// ─── DELETE /api/rooms/:id ────────────────────────────────────────────────────
router.delete('/:id', requireAuth, async (req, res) => {
  try {
    const room = await Room.findById(req.params.id);
    if (!room) return res.status(404).json({ error: 'Room not found' });

    if (room.creator.toString() !== req.session.userId) {
      return res.status(403).json({ error: 'Only the room creator can delete it' });
    }

    room.isActive = false;
    await room.save();

    logger.info(`Room deleted: ${room.code} by ${req.session.userId}`);
    res.json({ message: 'Room deleted' });

  } catch (err) {
    logger.error('DELETE /rooms/:id error:', err.message);
    res.status(500).json({ error: 'Failed to delete room' });
  }
});

module.exports = router;
