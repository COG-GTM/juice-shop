/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import express from 'express'
import request from 'supertest'
import { globalRateLimit, rateLimitKey } from '../../lib/rateLimiting'
const expect = chai.expect

function appWithLimit (limit: number) {
  const app = express()
  app.enable('trust proxy')
  app.use(globalRateLimit(60 * 1000, limit))
  app.get('/rest/user/whoami', (req, res) => { res.json({}) })
  return app
}

describe('globalRateLimit', () => {
  it('reads its default window and limit from config', async () => {
    const app = express()
    app.use(globalRateLimit())
    app.get('/', (req, res) => { res.send('ok') })

    const res = await request(app).get('/')
    expect(res.status).to.equal(200)
    expect(res.headers.ratelimit).to.match(/limit=1000/)
  })

  it('rejects requests over the per-client limit with 429', async () => {
    const app = appWithLimit(3)
    for (let i = 0; i < 3; i++) {
      expect((await request(app).get('/rest/user/whoami')).status).to.equal(200)
    }
    expect((await request(app).get('/rest/user/whoami')).status).to.equal(429)
  })

  it('cannot be reset by rotating X-Forwarded-For while trust proxy is enabled', async () => {
    const app = appWithLimit(3)
    const statuses: number[] = []
    for (let i = 0; i < 6; i++) {
      statuses.push((await request(app).get('/rest/user/whoami').set('X-Forwarded-For', `10.0.0.${i}`)).status)
    }
    expect(statuses).to.deep.equal([200, 200, 200, 429, 429, 429])
  })

  it('advertises the remaining budget in standard RateLimit headers', async () => {
    const res = await request(appWithLimit(5)).get('/rest/user/whoami')
    expect(res.headers.ratelimit).to.match(/limit=5, remaining=4/)
    expect(res.headers['x-ratelimit-limit']).to.equal(undefined)
  })

  it('shares one budget across an IPv6 /64 prefix', () => {
    expect(rateLimitKey('2001:db8:1:2:aaaa:bbbb:cccc:dddd')).to.equal('2001:db8:1:2::/64')
    expect(rateLimitKey('2001:db8:1:2::1')).to.equal('2001:db8:1:2::/64')
    expect(rateLimitKey('2001:0db8:0001:0002:0000:0000:0000:0042')).to.equal('2001:db8:1:2::/64')
    expect(rateLimitKey('2001:db8:1:3::1')).to.equal('2001:db8:1:3::/64')
    expect(rateLimitKey('::1')).to.equal('0:0:0:0::/64')
    expect(rateLimitKey('fe80::1%eth0')).to.equal('fe80:0:0:0::/64')
  })

  it('keys IPv4 and IPv4-mapped IPv6 addresses by the IPv4 address', () => {
    expect(rateLimitKey('203.0.113.7')).to.equal('203.0.113.7')
    expect(rateLimitKey('::ffff:203.0.113.7')).to.equal('203.0.113.7')
    expect(rateLimitKey(undefined)).to.equal('unknown')
  })
})
