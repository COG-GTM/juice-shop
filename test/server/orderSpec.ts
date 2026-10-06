/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import { campaignDiscountFor } from '../../routes/order'
const expect = chai.expect

const encode = (payload: string) => Buffer.from(payload).toString('base64')
const WMNSDY2019 = new Date('Mar 08, 2019 00:00:00 GMT+0100').getTime()
const ONE_HOUR = 60 * 60 * 1000

describe('campaignDiscountFor', () => {
  it('should grant the campaign discount on the campaign day', () => {
    expect(campaignDiscountFor(encode('WMNSDY2019'), WMNSDY2019)).to.equal(75)
    expect(campaignDiscountFor(encode('WMNSDY2019'), WMNSDY2019 + 23 * ONE_HOUR)).to.equal(75)
  })

  it('should not grant the campaign discount before or after the campaign day', () => {
    expect(campaignDiscountFor(encode('WMNSDY2019'), WMNSDY2019 - 1)).to.equal(0)
    expect(campaignDiscountFor(encode('WMNSDY2019'), WMNSDY2019 + 24 * ONE_HOUR)).to.equal(0)
  })

  it('should not grant an expired campaign discount for a client-supplied campaign timestamp', () => {
    expect(campaignDiscountFor(encode(`WMNSDY2019-${WMNSDY2019}`))).to.equal(0)
    expect(campaignDiscountFor(encode(`ORANGE2023-${new Date('May 04, 2023 00:00:00 GMT+0100').getTime()}`))).to.equal(0)
  })

  it('should not grant a discount for unknown or malformed coupon data', () => {
    expect(campaignDiscountFor(encode('NOSUCHCAMPAIGN'), WMNSDY2019)).to.equal(0)
    expect(campaignDiscountFor(encode('constructor'), WMNSDY2019)).to.equal(0)
    expect(campaignDiscountFor('', WMNSDY2019)).to.equal(0)
  })
})
