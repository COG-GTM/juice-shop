/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import crypto from 'node:crypto'
import chai from 'chai'
import { isSealed, open, parseKey, seal } from '../../lib/totpSecretStorage'
const expect = chai.expect

describe('totpSecretStorage', () => {
  const secret = 'IFTXE3SPOEYVURT2MRYGI52TKJ4HC3KH'

  it('stores no base32 seed in the sealed value', () => {
    const sealed = seal(secret)
    expect(isSealed(sealed)).to.equal(true)
    expect(sealed).to.not.include(secret)
  })

  it('round-trips a sealed secret', () => {
    expect(open(seal(secret))).to.equal(secret)
  })

  it('uses a fresh IV for every seal', () => {
    expect(seal(secret)).to.not.equal(seal(secret))
  })

  it('keeps an empty secret empty', () => {
    expect(seal('')).to.equal('')
    expect(open('')).to.equal('')
    expect(open(null)).to.equal('')
  })

  it('passes through unsealed legacy values', () => {
    expect(open(secret)).to.equal(secret)
  })

  it('rejects a tampered value', () => {
    const sealed = seal(secret)
    const tampered = sealed.slice(0, -2) + (sealed.endsWith('A') ? 'BB' : 'AA')
    expect(() => open(tampered)).to.throw()
  })

  it('rejects a value sealed with another key', () => {
    expect(() => open(seal(secret, crypto.randomBytes(32)))).to.throw()
  })

  describe('parseKey', () => {
    it('generates a random key when none is configured', () => {
      expect(parseKey(undefined)).to.have.lengthOf(32)
      expect(parseKey('')).to.have.lengthOf(32)
    })

    it('accepts hex and base64 encoded 32-byte keys', () => {
      const raw = crypto.randomBytes(32)
      expect(parseKey(raw.toString('hex')).equals(raw)).to.equal(true)
      expect(parseKey(raw.toString('base64')).equals(raw)).to.equal(true)
    })

    it('rejects keys of the wrong length', () => {
      expect(() => parseKey('too-short')).to.throw()
    })
  })
})
