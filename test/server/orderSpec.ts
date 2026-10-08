/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import { isCampaignActive } from '../../routes/order'
const expect = chai.expect

describe('order', () => {
  describe('isCampaignActive', () => {
    const campaign = { validOn: new Date('Mar 08, 2019 00:00:00 GMT+0100').getTime() }

    it('accepts a campaign coupon on its campaign day', () => {
      expect(isCampaignActive(campaign, campaign.validOn)).to.equal(true)
      expect(isCampaignActive(campaign, campaign.validOn + 23 * 60 * 60 * 1000)).to.equal(true)
    })

    it('rejects a campaign coupon after its campaign day', () => {
      expect(isCampaignActive(campaign, campaign.validOn + 24 * 60 * 60 * 1000)).to.equal(false)
      expect(isCampaignActive(campaign, Date.now())).to.equal(false)
    })

    it('rejects a campaign coupon before its campaign day', () => {
      expect(isCampaignActive(campaign, campaign.validOn - 1)).to.equal(false)
    })
  })
})
