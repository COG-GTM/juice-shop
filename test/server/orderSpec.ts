/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import { campaignDiscountFor } from '../../routes/order'
const expect = chai.expect

const encode = (payload: string) => Buffer.from(payload).toString('base64')
const WMNSDY2019 = new Date('Mar 08, 2019 00:00:00 GMT+0100').getTime()

describe('campaignDiscountFor', () => {
  it('should grant the campaign discount while the campaign day is ongoing', () => {
    expect(campaignDiscountFor(encode('WMNSDY2019'), WMNSDY2019)).to.equal(75)
  })

  it('should grant the campaign discount for any time of the campaign day', () => {
    expect(campaignDiscountFor(encode('WMNSDY2019'), WMNSDY2019 + 23 * 60 * 60 * 1000)).to.equal(75)
  })

  it('should not grant a discount after the campaign day has ended', () => {
    expect(campaignDiscountFor(encode('WMNSDY2019'), WMNSDY2019 + 24 * 60 * 60 * 1000)).to.equal(0)
  })

  it('should not grant a discount before the campaign day has begun', () => {
    expect(campaignDiscountFor(encode('WMNSDY2019'), WMNSDY2019 - 1)).to.equal(0)
  })

  it('should ignore a client-supplied timestamp matching the campaign date', () => {
    expect(campaignDiscountFor(encode(`WMNSDY2019-${WMNSDY2019}`), Date.now())).to.equal(0)
  })

  it('should not grant a discount for an unknown coupon code', () => {
    expect(campaignDiscountFor(encode('NOSUCHCAMPAIGN'), WMNSDY2019)).to.equal(0)
  })

  it('should not grant a discount for malformed coupon data', () => {
    expect(campaignDiscountFor('', WMNSDY2019)).to.equal(0)
    expect(campaignDiscountFor('not base64 at all!', WMNSDY2019)).to.equal(0)
  })
})
