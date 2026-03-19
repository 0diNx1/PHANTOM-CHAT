/**
 * PHANTOM CHAT - Authentication Routes
 * POST /api/auth/register  – Create anonymous user
 * POST /api/auth/login     – Re-claim identity with passphrase
 * POST /api/auth/logout    – End session
 * GET  /api/auth/me        – Get current session user
 */

'use strict';

const express = require('express');
const { body, validationResult } = require('express-validator');
const router  = express.Router();

const { User }  = require('../models');
const { generateToken } = require('../utils/encryption');
const logger    = require('../utils/logger');

// ─── Validation helpers ───────────────────────────────────────────────────────
const usernameRules = () =>
  body('username')
    .trim()
    .isLength({ min: 3, max: 20 })
    .matches(/^[a-zA-Z0-9_-]+$/)
    .withMessage('Username must be 3-20 alphanumeric chars, underscores, or hyphens');

const validate = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  next();
};

// ─── POST /api/auth/register ──────────────────────────────────────────────────
router.post('/register',
  usernameRules(),
  validate,
  async (req, res) => {
    try {
      const { username, passphrase, publicKey } = req.body;

      // Check username availability
      const existing = await User.findOne({ username });
      if (existing) {
        return res.status(409).json({ error: 'Username already taken' });
      }

      const sessionToken = generateToken(32);

      const user = new User({
        username,
        publicKey:      publicKey || null,
        sessionToken:   sessionToken,
        passphraseHash: passphrase || null, // Will be hashed by pre-save hook
      });

      await user.save();

      // Set server-side session
      req.session.userId   = user._id.toString();
      req.session.username = user.username;

      logger.info(`New user registered: ${username}`);

      res.status(201).json({
        message:  'User created',
        username: user.username,
        userId:   user._id,
        // Return token for client-side storage (optional secondary auth)
        token:    sessionToken,
      });

    } catch (err) {
      logger.error('Register error:', err.message);
      res.status(500).json({ error: 'Registration failed' });
    }
  }
);

// ─── POST /api/auth/login ─────────────────────────────────────────────────────
router.post('/login',
  usernameRules(),
  validate,
  async (req, res) => {
    try {
      const { username, passphrase } = req.body;

      const user = await User.findOne({ username });
      if (!user) {
        // Same response time as valid user to prevent enumeration
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      if (user.isBanned) {
        return res.status(403).json({ error: 'Account suspended' });
      }

      // If user has a passphrase set, verify it
      if (user.passphraseHash) {
        const ok = await user.verifyPassphrase(passphrase || '');
        if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
      }

      // Regenerate session to prevent fixation attacks
      req.session.regenerate(async (err) => {
        if (err) return res.status(500).json({ error: 'Session error' });

        req.session.userId   = user._id.toString();
        req.session.username = user.username;

        await User.findByIdAndUpdate(user._id, {
          isOnline: true,
          lastSeen: new Date(),
        });

        logger.info(`User logged in: ${username}`);

        res.json({
          message:   'Logged in',
          username:  user.username,
          userId:    user._id,
          publicKey: user.publicKey,
        });
      });

    } catch (err) {
      logger.error('Login error:', err.message);
      res.status(500).json({ error: 'Login failed' });
    }
  }
);

// ─── POST /api/auth/logout ────────────────────────────────────────────────────
router.post('/logout', async (req, res) => {
  try {
    if (req.session.userId) {
      await User.findByIdAndUpdate(req.session.userId, {
        isOnline: false,
        lastSeen: new Date(),
      });
    }

    req.session.destroy((err) => {
      if (err) logger.error('Session destroy error:', err.message);
      res.clearCookie('__phantom');
      res.json({ message: 'Logged out' });
    });

  } catch (err) {
    logger.error('Logout error:', err.message);
    res.status(500).json({ error: 'Logout failed' });
  }
});

// ─── GET /api/auth/me ─────────────────────────────────────────────────────────
router.get('/me', async (req, res) => {
  try {
    if (!req.session.userId) {
      return res.status(401).json({ error: 'Not authenticated' });
    }

    const user = await User.findById(req.session.userId)
      .select('-passphraseHash -sessionToken')
      .lean();

    if (!user) {
      req.session.destroy(() => {});
      return res.status(401).json({ error: 'User not found' });
    }

    res.json({ user });

  } catch (err) {
    logger.error('Me error:', err.message);
    res.status(500).json({ error: 'Failed to get user info' });
  }
});

module.exports = router;
