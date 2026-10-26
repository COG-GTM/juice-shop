/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import { adminPasswordOverride, securePrivilegedUsers } from '../../lib/seedCredentials'
import type { StaticUser } from '../../data/staticData'

const expect = chai.expect

describe('seedCredentials', () => {
  const admin: StaticUser = { email: 'admin', password: 'admin123', key: 'admin', role: 'admin', securityQuestion: { id: 2, answer: '@xI98PxDO+06!' } }
  const twoFactorAdmin: StaticUser = { email: 'wurstbrot', password: 'EinBelegtesBrotMitSchinkenSCHINKEN!', key: 'timo', role: 'admin', totpSecret: 'IFTXE3SPOEYVURT2MRYGI52TKJ4HC3KH', securityQuestion: { id: 1, answer: 'NZMJLjEinU7TFElDIYW8' } }
  const accountant: StaticUser = { email: 'accountant', password: 'i am an awesome accountant', key: 'accountant', role: 'accounting', securityQuestion: { id: 7, answer: 'sdAffsdfrefrbgreq3423' } }
  const customer: StaticUser = { email: 'jim', password: 'ncc-1701', key: 'jim', role: 'customer', securityQuestion: { id: 1, answer: 'Samuel' } }
  const users = [admin, twoFactorAdmin, accountant, customer]

  it('should replace published passwords of admin and accounting users with random ones', () => {
    const [securedAdmin, securedTwoFactorAdmin, securedAccountant] = securePrivilegedUsers(users, false, {})
    for (const [secured, original] of [[securedAdmin, admin], [securedTwoFactorAdmin, twoFactorAdmin], [securedAccountant, accountant]]) {
      expect(secured.password).to.not.equal(original.password)
      expect(secured.password).to.have.length.of.at.least(32)
      expect(secured.email).to.equal(original.email)
      expect(secured.role).to.equal(original.role)
    }
  })

  it('should replace published TOTP secrets and security answers of privileged users', () => {
    const [securedAdmin, securedTwoFactorAdmin, securedAccountant] = securePrivilegedUsers(users, false, {})
    expect(securedTwoFactorAdmin.totpSecret).to.match(/^[A-Z2-7]+=*$/)
    expect(securedTwoFactorAdmin.totpSecret).to.not.equal(twoFactorAdmin.totpSecret)
    expect(securedAdmin.totpSecret).to.equal(undefined)
    expect(securedAdmin.securityQuestion?.id).to.equal(admin.securityQuestion?.id)
    expect(securedAdmin.securityQuestion?.answer).to.not.equal(admin.securityQuestion?.answer)
    expect(securedAccountant.securityQuestion?.answer).to.not.equal(accountant.securityQuestion?.answer)
  })

  it('should generate different credentials on every startup', () => {
    const first = securePrivilegedUsers(users, false, {})
    const second = securePrivilegedUsers(users, false, {})
    expect(first[0].password).to.not.equal(second[0].password)
    expect(first[1].totpSecret).to.not.equal(second[1].totpSecret)
  })

  it('should leave non-privileged users unchanged', () => {
    expect(securePrivilegedUsers(users, false, {})[3]).to.deep.equal(customer)
  })

  it('should keep all published credentials when static privileged credentials are enabled', () => {
    expect(securePrivilegedUsers(users, true, {})).to.deep.equal(users)
  })

  it('should use JUICE_SHOP_ADMIN_PASSWORD for the admin account only', () => {
    const env = { JUICE_SHOP_ADMIN_PASSWORD: 'correct horse battery staple' }
    const [securedAdmin, securedTwoFactorAdmin] = securePrivilegedUsers(users, false, env)
    expect(securedAdmin.password).to.equal('correct horse battery staple')
    expect(securedTwoFactorAdmin.password).to.not.equal('correct horse battery staple')
  })

  it('should ignore an empty or published JUICE_SHOP_ADMIN_PASSWORD', () => {
    expect(adminPasswordOverride('admin123', { JUICE_SHOP_ADMIN_PASSWORD: '' })).to.equal(undefined)
    expect(adminPasswordOverride('admin123', { JUICE_SHOP_ADMIN_PASSWORD: 'admin123' })).to.equal(undefined)
    expect(securePrivilegedUsers(users, false, { JUICE_SHOP_ADMIN_PASSWORD: 'admin123' })[0].password).to.not.equal('admin123')
  })
})
