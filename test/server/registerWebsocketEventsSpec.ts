/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import { isSvgInjectionPayload } from '../../lib/startup/registerWebsocketEvents'

const expect = chai.expect

describe('registerWebsocketEvents', () => {
  describe('isSvgInjectionPayload', () => {
    it('accepts the intended challenge solution', () => {
      expect(isSvgInjectionPayload('../../../../redirect?to=https://placecats.com/g/200/100?x=https://github.com/juice-shop/juice-shop')).to.equal(true)
    })

    it('accepts the solution with a path prefix and without the g/ segment', () => {
      expect(isSvgInjectionPayload('foo/../../../juice-shop/redirect?to=http://placecats.com/200/100?x=https://github.com/juice-shop/juice-shop')).to.equal(true)
    })

    it('rejects payloads that do not use a redirect to placecats.com', () => {
      expect(isSvgInjectionPayload('../../../redirect?to=https://github.com/juice-shop/juice-shop')).to.equal(false)
    })

    it('rejects payloads that are not on the redirect allowlist', () => {
      expect(isSvgInjectionPayload('../../../redirect?to=https://placecats.com/g/200/100')).to.equal(false)
    })

    it('rejects non-string payloads', () => {
      expect(isSvgInjectionPayload(undefined)).to.equal(false)
      expect(isSvgInjectionPayload(42)).to.equal(false)
      expect(isSvgInjectionPayload(['../../../redirect?to=https://placecats.com/g/200/100?x=https://github.com/juice-shop/juice-shop'])).to.equal(false)
    })

    it('rejects oversized payloads even if they contain a valid solution', () => {
      expect(isSvgInjectionPayload('../../../redirect?to=https://placecats.com/g/200/100?x=https://github.com/juice-shop/juice-shop' + 'a'.repeat(2048))).to.equal(false)
    })

    it('evaluates a maximum-length adversarial payload in linear time', () => {
      const payload = '../../..' + '-/'.repeat(1020)
      const start = process.hrtime.bigint()
      for (let i = 0; i < 100; i++) {
        expect(isSvgInjectionPayload(payload)).to.equal(false)
      }
      expect(Number(process.hrtime.bigint() - start) / 1e6).to.be.below(1000)
    })
  })
})
