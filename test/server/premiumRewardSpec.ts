/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import { type Challenge } from 'data/types'
import { challenges } from '../../data/datacache'
import * as security from '../../lib/insecurity'
import { servePremiumContent } from '../../routes/premiumReward'

const expect = chai.expect
chai.use(sinonChai)

const deluxeEmail = 'ciso@juice-sh.op'
const deluxeToken = security.authorize({
  data: {
    email: deluxeEmail,
    role: security.roles.deluxe,
    deluxeToken: security.deluxeToken(deluxeEmail)
  }
})

describe('premiumReward', () => {
  let req: any
  let res: any
  let save: any

  beforeEach(() => {
    res = { sendFile: sinon.spy(), status: sinon.stub().returnsThis(), json: sinon.spy() }
    req = { headers: { authorization: 'Bearer ' + deluxeToken } }
    save = () => ({
      then () { }
    })
  })

  it('should serve /frontend/dist/frontend/assets/private/JuiceShop_Wallpaper_1920x1080_VR.jpg', () => {
    servePremiumContent()(req, res)

    expect(res.sendFile).to.have.been.calledWith(sinon.match(/frontend[/\\]dist[/\\]frontend[/\\]assets[/\\]private[/\\]JuiceShop_Wallpaper_1920x1080_VR\.jpg/))
  })

  it('should solve "premiumPaywallChallenge"', () => {
    challenges.premiumPaywallChallenge = { solved: false, save } as unknown as Challenge

    servePremiumContent()(req, res)

    expect(challenges.premiumPaywallChallenge.solved).to.equal(true)
  })

  it('should deny access for users without deluxe membership', () => {
    req = { headers: {} }
    challenges.premiumPaywallChallenge = { solved: false, save } as unknown as Challenge

    servePremiumContent()(req, res)

    expect(res.status).to.have.been.calledWith(403)
    expect(res.sendFile.called).to.equal(false)
    expect(challenges.premiumPaywallChallenge.solved).to.equal(false)
  })
})
