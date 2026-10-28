/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import request from 'supertest'
import type { Express } from 'express'
import config from 'config'
import { createTestApp } from './helpers/setup'

const operatorPassword = 'operator-chosen admin password'
let app: Express

before(async () => {
  delete process.env.JUICE_SHOP_DEMO_CREDENTIALS
  process.env.JUICE_SHOP_ADMIN_PASSWORD = operatorPassword
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

const adminEmail = `admin@${config.get<string>('application.domain')}`

void describe('admin account with JUICE_SHOP_ADMIN_PASSWORD', () => {
  void it('POST login accepts the operator-provided admin password', async () => {
    await request(app)
      .post('/rest/user/login')
      .set({ 'content-type': 'application/json' })
      .send({ email: adminEmail, password: operatorPassword })
      .expect(200)
  })

  void it('POST login rejects the documented admin password', async () => {
    await request(app)
      .post('/rest/user/login')
      .set({ 'content-type': 'application/json' })
      .send({ email: adminEmail, password: 'admin123' })
      .expect(401)
  })
})
