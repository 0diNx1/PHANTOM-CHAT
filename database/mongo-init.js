/**
 * PHANTOM CHAT - MongoDB Initialization Script
 * Runs once on first container start
 */

db = db.getSiblingDB('phantomchat');

// Create collections with validation
db.createCollection('users', {
  validator: {
    $jsonSchema: {
      bsonType: 'object',
      required: ['username'],
      properties: {
        username: { bsonType: 'string', minLength: 3, maxLength: 20 },
      },
    },
  },
});

db.createCollection('rooms');
db.createCollection('messages');

// Indexes
db.users.createIndex({ username: 1 }, { unique: true });
db.users.createIndex({ lastSeen: 1 }, { expireAfterSeconds: 30 * 24 * 3600 });

db.rooms.createIndex({ code: 1 }, { unique: true });
db.rooms.createIndex({ type: 1, isActive: 1 });
db.rooms.createIndex({ lastActivity: -1 });

db.messages.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 });
db.messages.createIndex({ room: 1, createdAt: -1 });

// Create a default public room
db.rooms.insertOne({
  name:            'general',
  code:            'MAIN-0001',
  type:            'public',
  topic:           'Main public channel — welcome to Phantom',
  members:         [],
  maxMembers:      100,
  autoDeleteHours: 24,
  isActive:        true,
  lastActivity:    new Date(),
  createdAt:       new Date(),
});

print('✓ Phantom Chat database initialized');
