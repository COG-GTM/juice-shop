/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

const crypto = require('node:crypto')

if (!process.env.JWT_PRIVATE_KEY && !process.env.JWT_PRIVATE_KEY_FILE) {
  process.env.JWT_PRIVATE_KEY = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 })
    .privateKey.export({ type: 'pkcs1', format: 'pem' }).toString()
}
if (!process.env.DELUXE_TOKEN_SECRET && !process.env.DELUXE_TOKEN_SECRET_FILE) {
  process.env.DELUXE_TOKEN_SECRET = crypto.randomBytes(32).toString('hex')
}
