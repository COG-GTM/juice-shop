import crypto from 'node:crypto'

process.env.NODE_ENV = 'test'
process.env.JWT_PRIVATE_KEY ??= crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ type: 'pkcs1', format: 'pem' }).toString()
