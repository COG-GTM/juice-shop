/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import { adminPasswordOverride, hasPublishedCredentials, secureSeedUsers } from '../../lib/seedCredentials'
import type { StaticUser } from '../../data/staticData'

const expect = chai.expect

describe('seedCredentials', () => {
  const admin: StaticUser = { email: 'admin', password: 'admin123', key: 'admin', role: 'admin', securityQuestion: { id: 2, answer: 'admin-answer' } }
  const twoFactorAdmin: StaticUser = { email: 'wurstbrot', password: 'published-2fa-password', key: 'timo', role: 'admin', totpSecret: 'IFTXE3SPOEYVURT2MRYGI52TKJ4HC3KH', securityQuestion: { id: 1, answer: 'timo-answer' } }
  const accountant: StaticUser = { email: 'accountant', password: 'published-accountant-password', key: 'accountant', role: 'accounting', securityQuestion: { id: 7, answer: 'accountant-answer' } }
  const rapper: StaticUser = { email: 'mc.safesearch', password: 'published-rapper-password', key: 'rapper', role: 'customer', securityQuestion: { id: 8, answer: 'rapper-answer' } }
  const amy: StaticUser = { email: 'amy', password: 'published-amy-password', key: 'amy', role: 'customer' }
  const customer: StaticUser = { email: 'jim', password: 'jim-password', key: 'jim', role: 'customer', securityQuestion: { id: 1, answer: 'Samuel' } }
  const users = [admin, twoFactorAdmin, accountant, rapper, amy, customer]

  it('should flag privileged users and customers whose passwords are published by challenges', () => {
    expect(users.map(hasPublishedCredentials)).to.deep.equal([true, true, true, true, true, false])
  })

  it('should replace published passwords with random ones', () => {
    const secured = secureSeedUsers(users, false, {})
    for (let i = 0; i < 5; i++) {
      expect(secured[i].password).to.not.equal(users[i].password)
      expect(secured[i].password).to.have.length.of.at.least(32)
      expect(secured[i].email).to.equal(users[i].email)
      expect(secured[i].role).to.equal(users[i].role)
    }
  })

  it('should replace published TOTP secrets and security answers', () => {
    const [securedAdmin, securedTwoFactorAdmin, securedAccountant, securedRapper, securedAmy] = secureSeedUsers(users, false, {})
    expect(securedTwoFactorAdmin.totpSecret).to.match(/^[A-Z2-7]{32}$/)
    expect(securedTwoFactorAdmin.totpSecret).to.not.equal(twoFactorAdmin.totpSecret)
    expect(securedAdmin.totpSecret).to.equal(undefined)
    expect(securedAdmin.securityQuestion?.id).to.equal(admin.securityQuestion?.id)
    expect(securedAdmin.securityQuestion?.answer).to.not.equal(admin.securityQuestion?.answer)
    expect(securedAccountant.securityQuestion?.answer).to.not.equal(accountant.securityQuestion?.answer)
    expect(securedRapper.securityQuestion?.answer).to.not.equal(rapper.securityQuestion?.answer)
    expect(securedAmy.securityQuestion).to.equal(undefined)
  })

  it('should generate different credentials on every startup', () => {
    const first = secureSeedUsers(users, false, {})
    const second = secureSeedUsers(users, false, {})
    expect(first[0].password).to.not.equal(second[0].password)
    expect(first[1].totpSecret).to.not.equal(second[1].totpSecret)
  })

  it('should leave other customers unchanged', () => {
    expect(secureSeedUsers(users, false, {})[5]).to.deep.equal(customer)
  })

  it('should keep all published credentials when static seed credentials are enabled', () => {
    expect(secureSeedUsers(users, true, {})).to.deep.equal(users)
  })

  it('should use JUICE_SHOP_ADMIN_PASSWORD for the admin account only', () => {
    const env = { JUICE_SHOP_ADMIN_PASSWORD: 'correct horse battery staple' }
    const [securedAdmin, securedTwoFactorAdmin] = secureSeedUsers(users, false, env)
    expect(securedAdmin.password).to.equal('correct horse battery staple')
    expect(securedTwoFactorAdmin.password).to.not.equal('correct horse battery staple')
  })

  it('should ignore a short or published JUICE_SHOP_ADMIN_PASSWORD', () => {
    expect(adminPasswordOverride('admin123', { JUICE_SHOP_ADMIN_PASSWORD: '' })).to.equal(undefined)
    expect(adminPasswordOverride('admin123', { JUICE_SHOP_ADMIN_PASSWORD: 'short' })).to.equal(undefined)
    expect(adminPasswordOverride('admin123', { JUICE_SHOP_ADMIN_PASSWORD: 'admin123' })).to.equal(undefined)
    expect(secureSeedUsers(users, false, { JUICE_SHOP_ADMIN_PASSWORD: 'admin123' })[0].password).to.not.equal('admin123')
  })
})
