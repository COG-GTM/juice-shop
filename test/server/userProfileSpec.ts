/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import { cspSourceAllowsInlineScripts } from '../../routes/userProfile'

const expect = chai.expect

describe('userProfile', () => {
  describe('cspSourceAllowsInlineScripts', () => {
    it('should detect a script-src directive allowing unsafe-inline', () => {
      expect(cspSourceAllowsInlineScripts("https://a.png; script-src 'unsafe-inline' 'self' 'unsafe-eval'")).to.equal(true)
      expect(cspSourceAllowsInlineScripts("x;script-src 'self' 'unsafe-inline'")).to.equal(true)
    })

    it('should not detect unsafe-inline outside of a script-src directive', () => {
      expect(cspSourceAllowsInlineScripts('https://a.png')).to.equal(false)
      expect(cspSourceAllowsInlineScripts("https://a.png; script-src 'self'")).to.equal(false)
      expect(cspSourceAllowsInlineScripts("'unsafe-inline'; script-src 'self'")).to.equal(false)
      expect(cspSourceAllowsInlineScripts("https://a.png script-src 'unsafe-inline'")).to.equal(false)
      expect(cspSourceAllowsInlineScripts("https://a.png; script-src\n'unsafe-inline'")).to.equal(false)
    })

    it('should evaluate a large repeated script-src value in linear time', () => {
      const start = Date.now()
      expect(cspSourceAllowsInlineScripts(';script-src'.repeat(100000))).to.equal(false)
      expect(Date.now() - start).to.be.below(500)
    })
  })
})
