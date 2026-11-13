/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import config from 'config'
import * as security from '../../lib/insecurity'
import { createTestApp } from './helpers/setup'
import { register } from './helpers/auth'

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

async function storedCredentials (email: string) {
  const res = await request(app)
    .get("/rest/products/search?q=')) union select id,'2','3',email,password,totpSecret,'7','8','9' from users--")
  assert.equal(res.status, 200)
  const row = res.body.data.find((item: any) => item.price === email)
  assert.ok(row, `Expected ${email} in UNION SELECT results`)
  return { password: row.deluxePrice as string, totpSecret: row.image as string }
}

void describe('stored user credentials', () => {
  void it('stores the seeded 2FA secret encrypted instead of in plaintext', async () => {
    const { totpSecret } = await storedCredentials(`wurstbrot@${config.get<string>('application.domain')}`)
    assert.notEqual(totpSecret, 'IFTXE3SPOEYVURT2MRYGI52TKJ4HC3KH')
    assert.ok(totpSecret.startsWith('enc:v1:'))
    assert.equal(security.decryptTotpSecret(totpSecret), 'IFTXE3SPOEYVURT2MRYGI52TKJ4HC3KH')
  })

  void it('stores a newly registered user password as salted scrypt hash and a fresh 2FA secret encrypted', async () => {
    const email = 'credential.storage@juice-sh.op'
    const password = 'Str0ng!Credential#Storage'
    const totpSecret = 'KDR5FXSOLNV6A5UAQYCKROSJZF7SVML7'
    await register(app, { email, password, totpSecret })

    const stored = await storedCredentials(email)
    assert.match(stored.password, /^scrypt\$/)
    assert.ok(await security.verifyPassword(password, stored.password))
    assert.notEqual(stored.totpSecret, totpSecret)
    assert.equal(security.decryptTotpSecret(stored.totpSecret), totpSecret)
  })
})
