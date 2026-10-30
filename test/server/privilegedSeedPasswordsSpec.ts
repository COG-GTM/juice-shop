/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import { seedPasswordFor, seedTotpSecretFor } from '../../data/privilegedSeedPasswords'
const expect = chai.expect

describe('privilegedSeedPasswords', () => {
  let previous: string | undefined

  beforeEach(() => {
    previous = process.env.JUICE_SHOP_DEMO_CREDENTIALS
    delete process.env.JUICE_SHOP_DEMO_CREDENTIALS
  })

  afterEach(() => {
    if (previous === undefined) delete process.env.JUICE_SHOP_DEMO_CREDENTIALS
    else process.env.JUICE_SHOP_DEMO_CREDENTIALS = previous
  })

  it('replaces the static password of admin accounts with a random one by default', () => {
    const first = seedPasswordFor({ role: 'admin', password: 'admin123' })
    const second = seedPasswordFor({ role: 'admin', password: 'admin123' })

    expect(first.generated).to.equal(true)
    expect(first.password).to.not.equal('admin123')
    expect(first.password).to.have.length.of.at.least(32)
    expect(first.password).to.not.equal(second.password)
  })

  it('replaces the static password of accounting accounts with a random one by default', () => {
    const seed = seedPasswordFor({ role: 'accounting', password: 'i am an awesome accountant' })

    expect(seed.generated).to.equal(true)
    expect(seed.password).to.not.equal('i am an awesome accountant')
  })

  it('keeps the static password of customer and deluxe accounts', () => {
    expect(seedPasswordFor({ role: 'customer', password: 'ncc-1701' })).to.deep.equal({ password: 'ncc-1701', generated: false })
    expect(seedPasswordFor({ role: 'deluxe', password: 'private' })).to.deep.equal({ password: 'private', generated: false })
  })

  it('keeps the static password of privileged accounts when demo credentials are explicitly enabled', () => {
    process.env.JUICE_SHOP_DEMO_CREDENTIALS = 'enabled'

    expect(seedPasswordFor({ role: 'admin', password: 'admin123' })).to.deep.equal({ password: 'admin123', generated: false })
  })

  it('does not treat other values as enabling demo credentials', () => {
    process.env.JUICE_SHOP_DEMO_CREDENTIALS = 'true'

    expect(seedPasswordFor({ role: 'admin', password: 'admin123' }).generated).to.equal(true)
  })

  it('replaces the static TOTP secret of privileged accounts with a random base32 secret by default', () => {
    const first = seedTotpSecretFor({ role: 'admin', totpSecret: 'IFTXE3SPOEYVURT2MRYGI52TKJ4HC3KH' })
    const second = seedTotpSecretFor({ role: 'admin', totpSecret: 'IFTXE3SPOEYVURT2MRYGI52TKJ4HC3KH' })

    expect(first).to.match(/^[A-Z2-7]{32}$/)
    expect(first).to.not.equal('IFTXE3SPOEYVURT2MRYGI52TKJ4HC3KH')
    expect(first).to.not.equal(second)
  })

  it('does not add a TOTP secret to privileged accounts without one', () => {
    expect(seedTotpSecretFor({ role: 'admin', totpSecret: undefined })).to.equal(undefined)
    expect(seedTotpSecretFor({ role: 'admin', totpSecret: '' })).to.equal('')
  })

  it('keeps the static TOTP secret of customer accounts and of privileged accounts when demo credentials are enabled', () => {
    expect(seedTotpSecretFor({ role: 'customer', totpSecret: 'KDR5FXSOLNV6A5UAQYCKROSJZF7SVML7' })).to.equal('KDR5FXSOLNV6A5UAQYCKROSJZF7SVML7')
    process.env.JUICE_SHOP_DEMO_CREDENTIALS = 'enabled'
    expect(seedTotpSecretFor({ role: 'admin', totpSecret: 'IFTXE3SPOEYVURT2MRYGI52TKJ4HC3KH' })).to.equal('IFTXE3SPOEYVURT2MRYGI52TKJ4HC3KH')
  })
})
