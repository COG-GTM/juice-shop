/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import { seedPasswordFor } from '../../data/privilegedSeedPasswords'
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
})
