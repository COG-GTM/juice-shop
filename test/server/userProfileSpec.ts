/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import { containsInterpolation, allowsUnsafeInlineScripts } from '../../routes/userProfile'
const expect = chai.expect

describe('userProfile', () => {
  describe('containsInterpolation', () => {
    it('matches the same values as /#{(.*)}/', () => {
      const samples = ['#{7*7}', 'a#{b}c', '#{}', '#{', '}#{', '#}', '#{\n}', 'x\n#{y}', '#{a\r}b}', 'plain', '', '#{a}\u2028', '#{#{']
      for (const sample of samples) {
        expect(containsInterpolation(sample), JSON.stringify(sample)).to.equal(/#{(.*)}/.exec(sample) !== null)
      }
    })

    it('handles missing values', () => {
      expect(containsInterpolation(undefined)).to.equal(false)
      expect(containsInterpolation(null)).to.equal(false)
    })

    it('runs in linear time on many unterminated starts', () => {
      const start = Date.now()
      expect(containsInterpolation('#{'.repeat(500000))).to.equal(false)
      expect(Date.now() - start).to.be.below(500)
    })
  })

  describe('allowsUnsafeInlineScripts', () => {
    it('matches the same values as /;[ ]*script-src(.)*\'unsafe-inline\'/', () => {
      const samples = [
        "https://a.png; script-src 'unsafe-inline' 'self' 'unsafe-eval'",
        "https://a.png;script-src 'unsafe-inline'",
        "https://a.png;   script-src'unsafe-inline'",
        "https://a.png; script-src 'self'",
        "https://a.png script-src 'unsafe-inline'",
        "https://a.png; script-src\n'unsafe-inline'",
        "'unsafe-inline'; script-src",
        "; script-src ; script-src 'unsafe-inline'",
        '/assets/public/images/uploads/default.svg',
        ''
      ]
      for (const sample of samples) {
        expect(allowsUnsafeInlineScripts(sample), JSON.stringify(sample)).to.equal(/;[ ]*script-src(.)*'unsafe-inline'/.exec(sample) !== null)
      }
    })

    it('handles missing values', () => {
      expect(allowsUnsafeInlineScripts(undefined)).to.equal(false)
      expect(allowsUnsafeInlineScripts(null)).to.equal(false)
    })

    it('runs in linear time on many unterminated directives', () => {
      const start = Date.now()
      expect(allowsUnsafeInlineScripts(';script-src'.repeat(100000))).to.equal(false)
      expect(Date.now() - start).to.be.below(500)
    })
  })
})
