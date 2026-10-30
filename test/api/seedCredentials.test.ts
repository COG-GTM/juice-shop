/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import config from 'config'
import { createTestApp } from './helpers/setup'

const domain = config.get<string>('application.domain')
const accountantPassword = 'configured-accountant-password'

let app: Express

before(async () => {
  delete process.env.JUICE_SHOP_INSECURE_SEED_CREDENTIALS
  process.env.JUICE_SHOP_SEED_PASSWORD_ACCOUNTANT = accountantPassword
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

async function loginStatus (email: string, password: string) {
  const res = await request(app)
    .post('/rest/user/login')
    .set({ 'content-type': 'application/json' })
    .send({ email, password })
  return res
}

void describe('seeded privileged accounts', () => {
  void it('admin cannot log in with the password from users.yml', async () => {
    const res = await loginStatus(`admin@${domain}`, 'admin123')
    assert.equal(res.status, 401)
  })

  void it('accountant cannot log in with the password from users.yml', async () => {
    const res = await loginStatus(`accountant@${domain}`, 'i am an awesome accountant')
    assert.equal(res.status, 401)
  })

  void it('2FA admin cannot log in with the password from users.yml', async () => {
    const res = await loginStatus(`wurstbrot@${domain}`, 'EinBelegtesBrotMitSchinkenSCHINKEN!')
    assert.equal(res.status, 401)
  })

  void it('accountant can log in with the password configured via environment', async () => {
    const res = await loginStatus(`accountant@${domain}`, accountantPassword)
    assert.equal(res.status, 200)
    assert.equal(typeof res.body.authentication.token, 'string')
  })

  void it('non-privileged seeded accounts keep their training credentials', async () => {
    const res = await loginStatus(`jim@${domain}`, 'ncc-1701')
    assert.equal(res.status, 200)
  })
})
