/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { authorizeMetricsScrape, hasValidScrapeToken, loadMetricsScrapeToken } from '../../lib/metricsScrapeToken'

const expect = chai.expect
chai.use(sinonChai)

const token = 'metrics-scrape-token-for-unit-tests-0123'

describe('metricsScrapeToken', () => {
  describe('loadMetricsScrapeToken', () => {
    it('returns the token from METRICS_SCRAPE_TOKEN', () => {
      expect(loadMetricsScrapeToken({ METRICS_SCRAPE_TOKEN: token })).to.equal(token)
    })

    it('reads the token from METRICS_SCRAPE_TOKEN_FILE', () => {
      const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'metrics-')), 'token')
      fs.writeFileSync(file, `${token}\n`)
      expect(loadMetricsScrapeToken({ METRICS_SCRAPE_TOKEN_FILE: file })).to.equal(token)
    })

    it('falls back to METRICS_SCRAPE_TOKEN_FILE when METRICS_SCRAPE_TOKEN is blank', () => {
      const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'metrics-')), 'token')
      fs.writeFileSync(file, token)
      expect(loadMetricsScrapeToken({ METRICS_SCRAPE_TOKEN: '  ', METRICS_SCRAPE_TOKEN_FILE: file })).to.equal(token)
    })

    it('disables metrics when no token is configured', () => {
      expect(loadMetricsScrapeToken({})).to.equal(undefined)
    })

    it('disables metrics when the token is too short', () => {
      expect(loadMetricsScrapeToken({ METRICS_SCRAPE_TOKEN: 'short' })).to.equal(undefined)
    })

    it('disables metrics when the token file cannot be read', () => {
      expect(loadMetricsScrapeToken({ METRICS_SCRAPE_TOKEN_FILE: '/nonexistent/metrics-token' })).to.equal(undefined)
    })
  })

  describe('hasValidScrapeToken', () => {
    it('accepts the configured bearer token', () => {
      expect(hasValidScrapeToken({ headers: { authorization: `Bearer ${token}` } } as any, token)).to.equal(true)
    })

    it('accepts the bearer scheme case-insensitively', () => {
      expect(hasValidScrapeToken({ headers: { authorization: `bearer ${token}` } } as any, token)).to.equal(true)
    })

    it('rejects a missing, malformed or different token', () => {
      expect(hasValidScrapeToken({ headers: {} } as any, token)).to.equal(false)
      expect(hasValidScrapeToken({ headers: { authorization: token } } as any, token)).to.equal(false)
      expect(hasValidScrapeToken({ headers: { authorization: `Basic ${token}` } } as any, token)).to.equal(false)
      expect(hasValidScrapeToken({ headers: { authorization: `Bearer ${token}x` } } as any, token)).to.equal(false)
      expect(hasValidScrapeToken({ headers: { authorization: `Bearer ${token.slice(1)}` } } as any, token)).to.equal(false)
    })
  })

  describe('authorizeMetricsScrape', () => {
    let res: any

    beforeEach(() => {
      res = { set: sinon.spy(), end: sinon.spy() }
      res.status = sinon.stub().returns(res)
    })

    it('responds 404 when metrics are disabled', () => {
      expect(authorizeMetricsScrape({ headers: { authorization: `Bearer ${token}` } } as any, res, undefined)).to.equal(false)
      expect(res.status).to.have.been.calledWith(404)
    })

    it('responds 401 with a bearer challenge when the token is wrong', () => {
      expect(authorizeMetricsScrape({ headers: { authorization: 'Bearer nope' } } as any, res, token)).to.equal(false)
      expect(res.status).to.have.been.calledWith(401)
      expect(res.set).to.have.been.calledWith('WWW-Authenticate', 'Bearer realm="metrics"')
    })

    it('lets the request through when the token matches', () => {
      expect(authorizeMetricsScrape({ headers: { authorization: `Bearer ${token}` } } as any, res, token)).to.equal(true)
      expect(res.status).to.have.callCount(0)
    })
  })
})
