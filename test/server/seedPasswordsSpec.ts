/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import { isProtectedSeedAccount, resolveSeedPassword, seedPasswordEnvVar } from '../../lib/seedPasswords'
const expect = chai.expect

describe('seedPasswords', () => {
  afterEach(() => {
    delete process.env[seedPasswordEnvVar('admin')]
    delete process.env[seedPasswordEnvVar('jim')]
  })

  it('treats admin-role and well-known customer accounts as protected', () => {
    expect(isProtectedSeedAccount('admin', 'admin')).to.equal(true)
    expect(isProtectedSeedAccount('LetUsTest', 'admin')).to.equal(true)
    expect(isProtectedSeedAccount('rapper', 'customer')).to.equal(true)
    expect(isProtectedSeedAccount('amy', 'customer')).to.equal(true)
    expect(isProtectedSeedAccount('jim', 'customer')).to.equal(false)
  })

  it('derives the environment variable name from the user key', () => {
    expect(seedPasswordEnvVar('admin')).to.equal('JUICE_SHOP_SEED_PASSWORD_ADMIN')
    expect(seedPasswordEnvVar('LetUsTest')).to.equal('JUICE_SHOP_SEED_PASSWORD_LETUSTEST')
  })

  it('replaces the static password of protected accounts with a random one by default', () => {
    const first = resolveSeedPassword({ key: 'admin', role: 'admin', password: 'static' }, false)
    const second = resolveSeedPassword({ key: 'admin', role: 'admin', password: 'static' }, false)
    expect(first.randomized).to.equal(true)
    expect(first.password).to.not.equal('static')
    expect(first.password).to.have.length.of.at.least(32)
    expect(first.password).to.not.equal(second.password)
  })

  it('keeps the static password of unprotected accounts', () => {
    expect(resolveSeedPassword({ key: 'jim', role: 'customer', password: 'static' }, false)).to.deep.equal({ password: 'static', randomized: false })
  })

  it('keeps static passwords of protected accounts when explicitly enabled', () => {
    expect(resolveSeedPassword({ key: 'admin', role: 'admin', password: 'static' }, true)).to.deep.equal({ password: 'static', randomized: false })
  })

  it('prefers a password configured via environment variable', () => {
    process.env[seedPasswordEnvVar('admin')] = 'fromEnv'
    process.env[seedPasswordEnvVar('jim')] = 'fromEnvToo'
    expect(resolveSeedPassword({ key: 'admin', role: 'admin', password: 'static' }, false)).to.deep.equal({ password: 'fromEnv', randomized: false })
    expect(resolveSeedPassword({ key: 'jim', role: 'customer', password: 'static' }, true)).to.deep.equal({ password: 'fromEnvToo', randomized: false })
  })
})
