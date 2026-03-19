/**
 * PHANTOM CHAT - Database Models
 * MongoDB Schemas with Mongoose
 *
 * Models:
 *   User    – Anonymous users with generated usernames
 *   Room    – Chat rooms (public/private/direct)
 *   Message – Encrypted messages with TTL auto-delete
 */

'use strict';

const mongoose = require('mongoose');
const bcrypt   = require('bcryptjs');
const { Schema } = mongoose;

// ─── User Schema ──────────────────────────────────────────────────────────────
/**
 * Anonymous users. No email required.
 * Username is auto-generated on the client, passphrase is optional.
 */
const userSchema = new Schema({
  username: {
    type:      String,
    required:  true,
    unique:    true,
    trim:      true,
    minlength: 3,
    maxlength: 20,
    // Only allow alphanumeric + underscores/hyphens
    match:     [/^[a-zA-Z0-9_-]+$/, 'Invalid username format'],
  },

  // Optional passphrase for re-claiming identity (hashed)
  passphraseHash: {
    type:    String,
    default: null,
  },

  // Ephemeral public key for E2E encryption (client-generated)
  publicKey: {
    type:    String,
    default: null,
  },

  // Track rooms the user has joined
  rooms: [{
    type: Schema.Types.ObjectId,
    ref:  'Room',
  }],

  // Session token for anonymous auth
  sessionToken: {
    type:    String,
    default: null,
  },

  // Whether user is currently online (managed via socket events)
  isOnline: {
    type:    Boolean,
    default: false,
  },

  // Soft-ban support
  isBanned: {
    type:    Boolean,
    default: false,
  },

  // Auto-delete anonymous users after inactivity (30 days)
  lastSeen: {
    type:    Date,
    default: Date.now,
  },

  createdAt: {
    type:    Date,
    default: Date.now,
  },
}, {
  timestamps: true,
  // Never return passphraseHash or sessionToken in JSON
  toJSON: {
    transform(doc, ret) {
      delete ret.passphraseHash;
      delete ret.sessionToken;
      delete ret.__v;
      return ret;
    },
  },
});

// TTL index: remove users inactive for 30 days
userSchema.index({ lastSeen: 1 }, { expireAfterSeconds: 30 * 24 * 3600 });
userSchema.index({ username: 1 }, { unique: true });

// Hash passphrase before saving
userSchema.pre('save', async function (next) {
  if (!this.isModified('passphraseHash') || !this.passphraseHash) return next();
  this.passphraseHash = await bcrypt.hash(this.passphraseHash, parseInt(process.env.BCRYPT_ROUNDS) || 12);
  next();
});

userSchema.methods.verifyPassphrase = function (passphrase) {
  if (!this.passphraseHash) return false;
  return bcrypt.compare(passphrase, this.passphraseHash);
};

const User = mongoose.model('User', userSchema);


// ─── Room Schema ──────────────────────────────────────────────────────────────
/**
 * Chat rooms:
 *   public  – anyone can join via room code
 *   private – invite-only, requires room password
 *   direct  – 1-to-1 between two users
 */
const roomSchema = new Schema({
  name: {
    type:      String,
    required:  true,
    trim:      true,
    maxlength: 50,
  },

  // Unique short code for joining (e.g., XKCD-9A1B)
  code: {
    type:     String,
    unique:   true,
    required: true,
    uppercase: true,
  },

  type: {
    type:    String,
    enum:    ['public', 'private', 'direct'],
    default: 'public',
  },

  // Hashed password for private rooms
  passwordHash: {
    type:    String,
    default: null,
  },

  creator: {
    type: Schema.Types.ObjectId,
    ref:  'User',
  },

  members: [{
    type: Schema.Types.ObjectId,
    ref:  'User',
  }],

  // Max members allowed
  maxMembers: {
    type:    Number,
    default: 50,
    max:     100,
  },

  // Topic/description
  topic: {
    type:    String,
    default: '',
    maxlength: 200,
  },

  // Auto-delete room after inactivity (hours, 0 = never)
  autoDeleteHours: {
    type:    Number,
    default: 0,
  },

  lastActivity: {
    type:    Date,
    default: Date.now,
  },

  isActive: {
    type:    Boolean,
    default: true,
  },

  createdAt: {
    type:    Date,
    default: Date.now,
  },
}, {
  timestamps: true,
  toJSON: {
    transform(doc, ret) {
      delete ret.passwordHash;
      delete ret.__v;
      return ret;
    },
  },
});

roomSchema.pre('save', async function (next) {
  if (!this.isModified('passwordHash') || !this.passwordHash) return next();
  this.passwordHash = await bcrypt.hash(this.passwordHash, 12);
  next();
});

roomSchema.methods.verifyPassword = function (password) {
  if (!this.passwordHash) return true; // No password set
  return bcrypt.compare(password, this.passwordHash);
};

const Room = mongoose.model('Room', roomSchema);


// ─── Message Schema ───────────────────────────────────────────────────────────
/**
 * Messages are stored encrypted.
 * The `content` field holds AES-256-GCM ciphertext (base64).
 * IV and authTag are stored separately for decryption.
 *
 * TTL index provides auto-delete functionality.
 */
const messageSchema = new Schema({
  room: {
    type:     Schema.Types.ObjectId,
    ref:      'Room',
    required: true,
    index:    true,
  },

  sender: {
    type:    Schema.Types.ObjectId,
    ref:     'User',
    default: null, // null = system message
  },

  senderUsername: {
    type:    String,
    required: true,
  },

  // Encrypted message content (AES-256-GCM ciphertext, base64)
  content: {
    type:     String,
    required: true,
  },

  // AES-GCM IV (base64)
  iv: {
    type:    String,
    default: null,
  },

  // AES-GCM auth tag (base64)
  authTag: {
    type:    String,
    default: null,
  },

  // Message type
  type: {
    type:    String,
    enum:    ['text', 'system', 'join', 'leave'],
    default: 'text',
  },

  // Whether message has been "read" (for direct messages)
  read: {
    type:    Boolean,
    default: false,
  },

  // Auto-delete timestamp (set by TTL index)
  expiresAt: {
    type:    Date,
    default: () => new Date(Date.now() + 24 * 3600 * 1000), // 24h default
  },

  createdAt: {
    type:    Date,
    default: Date.now,
  },
}, {
  timestamps: true,
  toJSON: {
    transform(doc, ret) {
      delete ret.__v;
      return ret;
    },
  },
});

// TTL index: MongoDB auto-deletes documents when expiresAt is reached
messageSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
messageSchema.index({ room: 1, createdAt: -1 });

const Message = mongoose.model('Message', messageSchema);


module.exports = { User, Room, Message };
