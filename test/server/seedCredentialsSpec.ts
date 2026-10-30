/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import { seedPasswordFor, seedSecurityAnswerFor, seedTotpSecretFor } from '../../data/seedCredentials'
const expect = chai.expect

describe('seedCredentials', () => {
  let previous: string | undefined

  beforeEach(() => {
    previous = process.env.JUICE_SHOP_DEMO_CREDENTIALS
    delete process.env.JUICE_SHOP_DEMO_CREDENTIALS
  })

  afterEach(() => {
    if (previous === undefined) delete process.env.JUICE_SHOP_DEMO_CREDENTIALS
    else process.env.JUICE_SHOP_DEMO_CREDENTIALS = previous
  })

  it('replaces the static password of a seeded account with a random one by default', () => {
    const first = seedPasswordFor('admin123')
    const second = seedPasswordFor('admin123')

    expect(first).to.not.equal('admin123')
    expect(first).to.have.length.of.at.least(32)
    expect(first).to.not.equal(second)
  })

  it('also replaces the static password of customer accounts by default', () => {
    expect(seedPasswordFor('demo')).to.not.equal('demo')
    expect(seedPasswordFor('ncc-1701')).to.not.equal('ncc-1701')
  })

  it('keeps the static password when demo credentials are explicitly enabled', () => {
    process.env.JUICE_SHOP_DEMO_CREDENTIALS = 'enabled'

    expect(seedPasswordFor('admin123')).to.equal('admin123')
    expect(seedPasswordFor('demo')).to.equal('demo')
  })

  it('does not treat other values as enabling demo credentials', () => {
    process.env.JUICE_SHOP_DEMO_CREDENTIALS = 'true'

    expect(seedPasswordFor('admin123')).to.not.equal('admin123')
  })

  it('replaces the static TOTP secret with a random base32 secret by default', () => {
    const first = seedTotpSecretFor('IFTXE3SPOEYVURT2MRYGI52TKJ4HC3KH')
    const second = seedTotpSecretFor('IFTXE3SPOEYVURT2MRYGI52TKJ4HC3KH')

    expect(first).to.match(/^[A-Z2-7]{32}$/)
    expect(first).to.not.equal('IFTXE3SPOEYVURT2MRYGI52TKJ4HC3KH')
    expect(first).to.not.equal(second)
  })

  it('does not add a TOTP secret to accounts without one', () => {
    expect(seedTotpSecretFor(undefined)).to.equal(undefined)
    expect(seedTotpSecretFor('')).to.equal('')
  })

  it('keeps the static TOTP secret when demo credentials are enabled', () => {
    process.env.JUICE_SHOP_DEMO_CREDENTIALS = 'enabled'
    expect(seedTotpSecretFor('IFTXE3SPOEYVURT2MRYGI52TKJ4HC3KH')).to.equal('IFTXE3SPOEYVURT2MRYGI52TKJ4HC3KH')
  })

  it('replaces the static security answer with a random one by default', () => {
    const first = seedSecurityAnswerFor('Samuel')
    const second = seedSecurityAnswerFor('Samuel')

    expect(first).to.not.equal('Samuel')
    expect(first).to.have.length.of.at.least(32)
    expect(first).to.not.equal(second)
  })

  it('keeps the static security answer when demo credentials are enabled', () => {
    process.env.JUICE_SHOP_DEMO_CREDENTIALS = 'enabled'
    expect(seedSecurityAnswerFor('West-2082')).to.equal('West-2082')
  })
})
