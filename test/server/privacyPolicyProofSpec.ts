/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import { type Challenge } from 'data/types'
import { challenges } from '../../data/datacache'
import { servePrivacyPolicyProof } from '../../routes/privacyPolicyProof'

const expect = chai.expect
chai.use(sinonChai)

describe('privacyPolicyProof', () => {
  const originalChallenges = { ...challenges }

  after(() => {
    for (const key of Object.keys(challenges)) {
      delete challenges[key]
    }
    Object.assign(challenges, originalChallenges)
  })

  let req: any
  let res: any
  let save: any

  beforeEach(() => {
    req = {}
    res = { sendFile: sinon.spy() }
    save = () => ({
      then () { }
    })
  })

  it('should serve thank-you image from private assets', () => {
    challenges.privacyPolicyProofChallenge = { solved: true, save } as unknown as Challenge

    servePrivacyPolicyProof()(req, res)

    expect(res.sendFile).to.have.been.calledWith(sinon.match(/frontend[/\\]dist[/\\]frontend[/\\]assets[/\\]private[/\\]thank-you\.jpg/))
  })

  it('should solve "privacyPolicyProofChallenge"', () => {
    challenges.privacyPolicyProofChallenge = { solved: false, save } as unknown as Challenge

    servePrivacyPolicyProof()(req, res)

    expect(challenges.privacyPolicyProofChallenge.solved).to.equal(true)
  })
})
