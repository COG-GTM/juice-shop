/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import { seedPasswordFor } from '../../data/privilegedSeedPasswords'
const expect = chai.expect

describe('privilegedSeedPasswords', () => {
  const envVars = ['JUICE_SHOP_DEMO_CREDENTIALS', 'JUICE_SHOP_ADMIN_PASSWORD']
  let previous: Record<string, string | undefined>

  beforeEach(() => {
    previous = Object.fromEntries(envVars.map(name => [name, process.env[name]]))
    envVars.forEach(name => { delete process.env[name] })
  })

  afterEach(() => {
    envVars.forEach(name => {
      if (previous[name] === undefined) delete process.env[name]
      else process.env[name] = previous[name]
    })
  })

  it('replaces the static password of admin accounts with a random one by default', () => {
    const first = seedPasswordFor({ key: 'admin', role: 'admin', password: 'admin123' })
    const second = seedPasswordFor({ key: 'admin', role: 'admin', password: 'admin123' })

    expect(first.source).to.equal('generated')
    expect(first.password).to.not.equal('admin123')
    expect(first.password).to.have.length.of.at.least(32)
    expect(first.password).to.not.equal(second.password)
  })

  it('replaces the static password of accounting accounts with a random one by default', () => {
    const seed = seedPasswordFor({ key: 'accountant', role: 'accounting', password: 'i am an awesome accountant' })

    expect(seed.source).to.equal('generated')
    expect(seed.password).to.not.equal('i am an awesome accountant')
  })

  it('keeps the static password of customer and deluxe accounts', () => {
    expect(seedPasswordFor({ key: 'jim', role: 'customer', password: 'ncc-1701' })).to.deep.equal({ password: 'ncc-1701', source: 'static' })
    expect(seedPasswordFor({ key: 'bjoernOwasp', role: 'deluxe', password: 'private' })).to.deep.equal({ password: 'private', source: 'static' })
  })

  it('keeps the static password of privileged accounts when demo credentials are explicitly enabled', () => {
    process.env.JUICE_SHOP_DEMO_CREDENTIALS = 'enabled'

    expect(seedPasswordFor({ key: 'admin', role: 'admin', password: 'admin123' })).to.deep.equal({ password: 'admin123', source: 'static' })
  })

  it('does not treat other values as enabling demo credentials', () => {
    process.env.JUICE_SHOP_DEMO_CREDENTIALS = 'true'

    expect(seedPasswordFor({ key: 'admin', role: 'admin', password: 'admin123' }).source).to.equal('generated')
  })

  it('uses JUICE_SHOP_ADMIN_PASSWORD for the main admin account', () => {
    process.env.JUICE_SHOP_ADMIN_PASSWORD = 'correct horse battery staple'

    expect(seedPasswordFor({ key: 'admin', role: 'admin', password: 'admin123' })).to.deep.equal({ password: 'correct horse battery staple', source: 'operator' })
  })

  it('does not apply JUICE_SHOP_ADMIN_PASSWORD to other privileged accounts', () => {
    process.env.JUICE_SHOP_ADMIN_PASSWORD = 'correct horse battery staple'

    const seed = seedPasswordFor({ key: 'accountant', role: 'accounting', password: 'i am an awesome accountant' })
    expect(seed.source).to.equal('generated')
    expect(seed.password).to.not.equal('correct horse battery staple')
  })

  it('ignores a JUICE_SHOP_ADMIN_PASSWORD shorter than the minimum length', () => {
    process.env.JUICE_SHOP_ADMIN_PASSWORD = 'admin123'

    const seed = seedPasswordFor({ key: 'admin', role: 'admin', password: 'admin123' })
    expect(seed.source).to.equal('generated')
    expect(seed.password).to.not.equal('admin123')
  })
})
