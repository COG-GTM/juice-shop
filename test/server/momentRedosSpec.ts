/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { createRequire } from 'node:module'
import semver from 'semver'
import chai from 'chai'
const expect = chai.expect

const requireFromExpressJwt = createRequire(require.resolve('express-jwt'))
const requireFromJsonwebtoken = createRequire(requireFromExpressJwt.resolve('jsonwebtoken'))
const moment = requireFromJsonwebtoken('moment')

describe('moment (via express-jwt > jsonwebtoken)', () => {
  it('resolves to a version fixed for CVE-2017-18214', () => {
    expect(semver.gte(moment.version, '2.19.3')).to.equal(true)
  })

  it('parses a long non-date token in linear time', () => {
    const start = Date.now()
    moment('1'.repeat(80000), 'MMM')
    expect(Date.now() - start).to.be.below(1500)
  })
})
