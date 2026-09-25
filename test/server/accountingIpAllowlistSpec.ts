/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import express from 'express'
import { IpDeniedError } from 'express-ipfilter'
import request from 'supertest'
import { accountingIpFilter, isValidIpOrCidr } from '../../lib/accountingIpAllowlist'
const expect = chai.expect

const appWithAllowlist = (allowlist: string[]) => {
  const app = express()
  app.set('trust proxy', true)
  app.use('/quantity', ...accountingIpFilter(allowlist), (req: express.Request, res: express.Response) => { res.sendStatus(200) })
  app.use((err: Error, req: express.Request, res: express.Response, next: express.NextFunction) => { res.sendStatus(err instanceof IpDeniedError ? 403 : 500) })
  return app
}

describe('accountingIpAllowlist', () => {
  describe('isValidIpOrCidr', () => {
    it('should accept IPv4 and IPv6 addresses', () => {
      expect(isValidIpOrCidr('192.168.0.1')).to.equal(true)
      expect(isValidIpOrCidr('::1')).to.equal(true)
    })

    it('should accept CIDR ranges within the prefix limits of their IP version', () => {
      expect(isValidIpOrCidr('10.0.0.0/8')).to.equal(true)
      expect(isValidIpOrCidr('2001:db8::/32')).to.equal(true)
      expect(isValidIpOrCidr('10.0.0.0/33')).to.equal(false)
      expect(isValidIpOrCidr('2001:db8::/129')).to.equal(false)
    })

    it('should reject malformed entries', () => {
      expect(isValidIpOrCidr('123.456.789')).to.equal(false)
      expect(isValidIpOrCidr('192.168.0.1/24/8')).to.equal(false)
      expect(isValidIpOrCidr('')).to.equal(false)
    })
  })

  describe('accountingIpFilter', () => {
    it('should not apply any filter for an empty allowlist', () => {
      expect(accountingIpFilter([])).to.have.lengthOf(0)
    })

    it('should apply a single filter middleware for a valid allowlist', () => {
      expect(accountingIpFilter(['10.0.0.0/8', '::1'])).to.have.lengthOf(1)
    })

    it('should throw on a malformed allowlist entry', () => {
      expect(() => accountingIpFilter(['123.456.789'])).to.throw('123.456.789')
    })
  })

  describe('request filtering', () => {
    it('should pass requests through when no allowlist is configured', async () => {
      const res = await request(appWithAllowlist([])).get('/quantity')
      expect(res.status).to.equal(200)
    })

    it('should allow a client whose address is covered by the allowlist', async () => {
      const res = await request(appWithAllowlist(['127.0.0.0/8', '::1'])).get('/quantity')
      expect(res.status).to.equal(200)
    })

    it('should deny a client whose address is not covered by the allowlist', async () => {
      const res = await request(appWithAllowlist(['10.0.0.0/8'])).get('/quantity')
      expect(res.status).to.equal(403)
    })

    it('should not let a spoofed X-Forwarded-For header pass the allowlist', async () => {
      const res = await request(appWithAllowlist(['10.0.0.0/8'])).get('/quantity').set('X-Forwarded-For', '10.0.0.1')
      expect(res.status).to.equal(403)
    })
  })
})
