/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import express, { type Request, type Response } from 'express'
import request from 'supertest'
import chai from 'chai'

import * as rateLimiting from '../../lib/rateLimiting'

const expect = chai.expect

const requestWithBody = (body: any) => ({ body }) as unknown as Request

describe('rateLimiting', () => {
  describe('trustedProxyHops', () => {
    it('does not trust any proxy by default', () => {
      expect(rateLimiting.trustedProxyHops(undefined)).to.equal(false)
      expect(rateLimiting.trustedProxyHops('')).to.equal(false)
    })

    it('trusts the configured number of proxy hops', () => {
      expect(rateLimiting.trustedProxyHops('1')).to.equal(1)
      expect(rateLimiting.trustedProxyHops('2')).to.equal(2)
    })

    it('rejects values that would trust every hop or are invalid', () => {
      expect(rateLimiting.trustedProxyHops('true')).to.equal(false)
      expect(rateLimiting.trustedProxyHops('0')).to.equal(false)
      expect(rateLimiting.trustedProxyHops('-1')).to.equal(false)
      expect(rateLimiting.trustedProxyHops('1.5')).to.equal(false)
      expect(rateLimiting.trustedProxyHops('loopback')).to.equal(false)
    })
  })

  describe('accountRateLimit', () => {
    it('counts failed attempts per account across different client addresses', async () => {
      const app = express()
      app.set('trust proxy', true)
      app.use(express.json())
      const seenIps = new Set<string>()
      app.post('/reset', rateLimiting.accountRateLimit(rateLimiting.emailOf), (req: Request, res: Response) => {
        seenIps.add(String(req.ip))
        rateLimiting.markFailedAttempt(res)
        res.status(401).end()
      })

      const statuses: number[] = []
      for (let i = 1; i <= 11; i++) {
        const res = await request(app).post('/reset').set('X-Forwarded-For', `198.51.100.${i}`).send({ email: 'victim@juice-sh.op' })
        statuses.push(res.status)
      }

      expect(seenIps.size).to.equal(10)
      expect(statuses.slice(0, 10)).to.deep.equal(Array(10).fill(401))
      expect(statuses[10]).to.equal(429)
      const other = await request(app).post('/reset').set('X-Forwarded-For', '198.51.100.99').send({ email: 'other@juice-sh.op' })
      expect(other.status).to.equal(401)
    })
  })

  describe('emailOf', () => {
    it('keys on the exact email the reset route looks up', () => {
      expect(rateLimiting.emailOf(requestWithBody({ email: 'Jim@Juice-sh.op' }))).to.equal('Jim@Juice-sh.op')
      expect(rateLimiting.emailOf(requestWithBody({ email: 'jim@juice-sh.op' }))).to.equal('jim@juice-sh.op')
    })

    it('puts all non-string emails into one shared bucket', () => {
      expect(rateLimiting.emailOf(requestWithBody({ email: ['a@b.c'] }))).to.equal('<non-string>')
      expect(rateLimiting.emailOf(requestWithBody({ email: { $like: '%' } }))).to.equal('<non-string>')
      expect(rateLimiting.emailOf(requestWithBody({ email: 1 }))).to.equal('<non-string>')
    })

    it('returns undefined without a usable email', () => {
      expect(rateLimiting.emailOf(requestWithBody({}))).to.equal(undefined)
      expect(rateLimiting.emailOf(requestWithBody({ email: '  ' }))).to.equal(undefined)
      expect(rateLimiting.emailOf(requestWithBody(undefined))).to.equal(undefined)
    })
  })
})
