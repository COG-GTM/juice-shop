/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import { secureStaticUser } from '../../data/datacreator'
import type { StaticUser } from '../../data/staticData'

const expect = chai.expect

describe('datacreator', () => {
  describe('secureStaticUser', () => {
    const admin: StaticUser = {
      email: 'wurstbrot',
      password: 'EinBelegtesBrotMitSchinkenSCHINKEN!',
      totpSecret: 'IFTXE3SPOEYVURT2MRYGI52TKJ4HC3KH',
      key: 'timo',
      role: 'admin',
      securityQuestion: { id: 1, answer: 'NZMJLjEinU7TFElDIYW8' }
    }
    const customer: StaticUser = {
      email: 'jim',
      password: 'ncc-1701',
      key: 'jim',
      role: 'customer',
      securityQuestion: { id: 1, answer: 'Samuel' }
    }

    it('should replace static password, TOTP secret and security answer of admin accounts with random values', () => {
      const secured = secureStaticUser(admin, false)
      expect(secured.password).to.not.equal(admin.password)
      expect(secured.password).to.have.length.of.at.least(32)
      expect(secured.totpSecret).to.not.equal(admin.totpSecret)
      expect(secured.totpSecret).to.match(/^[A-Z2-7]+=*$/)
      expect(secured.securityQuestion?.id).to.equal(admin.securityQuestion?.id)
      expect(secured.securityQuestion?.answer).to.not.equal(admin.securityQuestion?.answer)
      expect(secured.email).to.equal(admin.email)
      expect(secured.role).to.equal('admin')
    })

    it('should generate different credentials on every call', () => {
      const first = secureStaticUser(admin, false)
      const second = secureStaticUser(admin, false)
      expect(first.password).to.not.equal(second.password)
      expect(first.totpSecret).to.not.equal(second.totpSecret)
    })

    it('should not add a TOTP secret to admin accounts without 2FA', () => {
      const secured = secureStaticUser({ ...admin, totpSecret: undefined }, false)
      expect(secured.totpSecret).to.equal(undefined)
    })

    it('should keep static admin credentials when explicitly configured', () => {
      expect(secureStaticUser(admin, true)).to.deep.equal(admin)
    })

    it('should leave non-admin accounts unchanged', () => {
      expect(secureStaticUser(customer, false)).to.deep.equal(customer)
    })
  })
})
