/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import { isCampaignActive } from '../../routes/order'
const expect = chai.expect

describe('order', () => {
  describe('isCampaignActive', () => {
    const validOn = new Date('Mar 08, 2019 00:00:00 GMT+0100').getTime()

    it('is active during the campaign day', () => {
      expect(isCampaignActive(validOn, validOn)).to.equal(true)
      expect(isCampaignActive(validOn, validOn + 23 * 60 * 60 * 1000)).to.equal(true)
    })

    it('is inactive before and after the campaign day', () => {
      expect(isCampaignActive(validOn, validOn - 1)).to.equal(false)
      expect(isCampaignActive(validOn, validOn + 24 * 60 * 60 * 1000)).to.equal(false)
      expect(isCampaignActive(validOn, Date.now())).to.equal(false)
    })
  })
})
