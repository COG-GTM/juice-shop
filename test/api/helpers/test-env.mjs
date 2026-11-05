import crypto from 'node:crypto'

process.env.NODE_ENV = 'test'

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
const randomBase32 = (length) => Array.from(crypto.randomBytes(length), (byte) => BASE32_ALPHABET[byte % 32]).join('')

for (const key of ['ADMIN', 'SUPPORT', 'JANNIK', 'TIMO', 'BJOERN', 'BJOERNGOOGLE', 'LETUSTEST']) {
  process.env[`JUICE_SHOP_${key}_PASSWORD`] ??= crypto.randomBytes(18).toString('base64url')
}
process.env.JUICE_SHOP_TIMO_TOTP_SECRET ??= randomBase32(32)
