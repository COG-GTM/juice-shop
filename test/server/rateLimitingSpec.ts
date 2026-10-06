/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import express from 'express'
import request from 'supertest'
import { accountRateLimit, clientRateLimit, emailOf, trustedProxyHops } from '../../lib/rateLimiting'

const expect = chai.expect

function appWith (trustProxy: number | boolean, ...limiters: express.RequestHandler[]) {
  const app = express()
  app.set('trust proxy', trustProxy)
  app.use(express.json())
  app.post('/target', ...limiters, (req, res) => { res.status(401).send() })
  return app
}

async function hammer (app: express.Express, times: number, body: Record<string, unknown> = {}) {
  let res
  for (let i = 0; i < times; i++) {
    res = await request(app).post('/target').set('X-Forwarded-For', `10.0.${Math.floor(i / 250)}.${i % 250}`).send(body)
  }
  return res
}

describe('rateLimiting', () => {
  describe('trustedProxyHops', () => {
    it('does not trust any proxy by default', () => {
      expect(trustedProxyHops(undefined)).to.equal(false)
      expect(trustedProxyHops('')).to.equal(false)
      expect(trustedProxyHops('0')).to.equal(false)
    })

    it('rejects values that would trust arbitrary hops', () => {
      expect(trustedProxyHops('true')).to.equal(false)
      expect(trustedProxyHops('-1')).to.equal(false)
      expect(trustedProxyHops('1.5')).to.equal(false)
    })

    it('trusts the configured number of proxy hops', () => {
      expect(trustedProxyHops('1')).to.equal(1)
      expect(trustedProxyHops('2')).to.equal(2)
    })
  })

  describe('clientRateLimit', () => {
    it('cannot be bypassed by rotating X-Forwarded-For when no proxy is trusted', async () => {
      const app = appWith(trustedProxyHops(undefined), clientRateLimit(5))
      expect((await hammer(app, 5))?.status).to.equal(401)
      expect((await hammer(app, 1))?.status).to.equal(429)
    })
  })

  describe('accountRateLimit', () => {
    it('limits attempts against one account even when every request appears to come from a new client', async () => {
      const app = appWith(1, accountRateLimit(emailOf, 3))
      expect((await hammer(app, 3, { email: 'Morty@juice-sh.op' }))?.status).to.equal(401)
      expect((await hammer(app, 1, { email: ' morty@juice-sh.op ' }))?.status).to.equal(429)
      expect((await hammer(app, 1, { email: 'jim@juice-sh.op' }))?.status).to.equal(401)
    })

    it('falls back to the client address when no account can be determined', async () => {
      const app = appWith(false, accountRateLimit(() => { throw new Error('unparsable') }, 2))
      expect((await hammer(app, 2))?.status).to.equal(401)
      expect((await hammer(app, 1))?.status).to.equal(429)
    })
  })

  describe('emailOf', () => {
    it('normalizes the email from the request body', () => {
      expect(emailOf({ body: { email: ' Admin@Juice-Sh.op ' } } as any)).to.equal('admin@juice-sh.op')
      expect(emailOf({ body: { email: { $ne: 1 } } } as any)).to.equal(undefined)
      expect(emailOf({ body: undefined } as any)).to.equal(undefined)
    })
  })
})
