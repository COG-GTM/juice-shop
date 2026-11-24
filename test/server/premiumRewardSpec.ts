/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import { type Challenge } from 'data/types'
import { challenges } from '../../data/datacache'
import { servePremiumContent } from '../../routes/premiumReward'
import * as security from '../../lib/insecurity'

const expect = chai.expect
chai.use(sinonChai)

function bearer (data: Record<string, unknown>) {
  return { headers: { authorization: 'Bearer ' + security.authorize({ data }) } }
}

describe('premiumReward', () => {
  let req: any
  let res: any
  let save: any

  beforeEach(() => {
    res = { sendFile: sinon.spy(), status: sinon.stub().returnsThis(), json: sinon.spy() }
    req = bearer({ email: 'ciso@juice-sh.op', role: security.roles.deluxe, deluxeToken: security.deluxeToken('ciso@juice-sh.op') })
    save = () => ({
      then () { }
    })
  })

  it('should serve the premium wallpaper from outside the static web root to deluxe members', () => {
    servePremiumContent()(req, res)

    expect(res.sendFile).to.have.been.calledWith(sinon.match(/data[/\\]static[/\\]premium[/\\]JuiceShop_Wallpaper_1920x1080_VR\.jpg/))
  })

  it('should solve "premiumPaywallChallenge" for deluxe members', () => {
    challenges.premiumPaywallChallenge = { solved: false, save } as unknown as Challenge

    servePremiumContent()(req, res)

    expect(challenges.premiumPaywallChallenge.solved).to.equal(true)
  })

  it('should refuse requests without a token', () => {
    challenges.premiumPaywallChallenge = { solved: false, save } as unknown as Challenge

    servePremiumContent()({ headers: {} } as any, res)

    expect(res.status).to.have.been.calledWith(403)
    expect(res.sendFile).to.have.callCount(0)
    expect(challenges.premiumPaywallChallenge.solved).to.equal(false)
  })

  it('should refuse regular customers', () => {
    servePremiumContent()(bearer({ email: 'bender@juice-sh.op', role: security.roles.customer }) as any, res)

    expect(res.status).to.have.been.calledWith(403)
    expect(res.sendFile).to.have.callCount(0)
  })

  it('should refuse a deluxe role without a valid deluxe token', () => {
    servePremiumContent()(bearer({ email: 'bender@juice-sh.op', role: security.roles.deluxe, deluxeToken: 'forged' }) as any, res)

    expect(res.status).to.have.been.calledWith(403)
    expect(res.sendFile).to.have.callCount(0)
  })
})
