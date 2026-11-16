import crypto from 'node:crypto'

process.env.NODE_ENV = 'test'
process.env.JUICE_SHOP_ADMIN_PASSWORD ??= crypto.randomBytes(24).toString('base64url')
