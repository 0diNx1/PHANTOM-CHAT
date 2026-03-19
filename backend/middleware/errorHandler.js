'use strict';

const logger = require('../utils/logger');

function errorHandler(err, req, res, next) {
  logger.error(`${err.status || 500} - ${err.message} - ${req.originalUrl} - ${req.method} - ${req.ip}`);

  // Don't leak stack traces in production
  const response = {
    error: process.env.NODE_ENV === 'production' ? 'Internal server error' : err.message,
  };

  if (process.env.NODE_ENV !== 'production') {
    response.stack = err.stack;
  }

  res.status(err.status || 500).json(response);
}

module.exports = { errorHandler };
