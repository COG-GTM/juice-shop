/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import config from 'config'
import { retrieveAppConfiguration } from '../../routes/appConfiguration'
const expect = chai.expect
chai.use(sinonChai)

describe('appConfiguration', () => {
  let req: any
  let res: any

  function retrieveConfig () {
    req = {}
    res = { json: sinon.spy() }
    retrieveAppConfiguration()(req, res)
    return res.json.firstCall.args[0].config
  }

  it('should return configuration object', () => {
    const returnedConfig = retrieveConfig()
    // eslint-disable-next-line @typescript-eslint/no-unused-expressions
    expect(res.json).to.have.been.calledOnce
    // eslint-disable-next-line @typescript-eslint/no-unused-expressions
    expect(returnedConfig.application).to.exist
  })

  it('should return public UI settings needed by the frontend', () => {
    const returnedConfig = retrieveConfig()
    expect(returnedConfig.application.name).to.equal(config.get('application.name'))
    expect(returnedConfig.application.domain).to.equal(config.get('application.domain'))
    expect(returnedConfig.application.welcomeBanner).to.deep.equal(config.util.toObject(config.get('application.welcomeBanner')))
    expect(returnedConfig.application.chatBot.name).to.equal(config.get('application.chatBot.name'))
    expect(returnedConfig.application.googleOauth.clientId).to.equal(config.get('application.googleOauth.clientId'))
    expect(returnedConfig.challenges.codingChallengesEnabled).to.equal(config.get('challenges.codingChallengesEnabled'))
    expect(returnedConfig.hackingInstructor.isEnabled).to.equal(config.get('hackingInstructor.isEnabled'))
    expect(returnedConfig.ctf.showFlagsInNotifications).to.equal(config.get('ctf.showFlagsInNotifications'))
  })

  it('should not expose chatBot.llmApiUrl', () => {
    const returnedConfig = retrieveConfig()
    // eslint-disable-next-line @typescript-eslint/no-unused-expressions
    expect(returnedConfig.application.chatBot).to.exist
    expect(returnedConfig.application.chatBot).to.not.have.property('llmApiUrl')
  })

  it('should not expose memories, products or server settings', () => {
    const returnedConfig = retrieveConfig()
    expect(returnedConfig).to.not.have.property('memories')
    expect(returnedConfig).to.not.have.property('products')
    expect(returnedConfig).to.not.have.property('server')
  })

  it('should not expose any security answers', () => {
    const serializedConfig = JSON.stringify(retrieveConfig())
    expect(serializedConfig).to.not.match(/SecurityAnswer/)
    for (const memory of config.get<any[]>('memories')) {
      for (const answer of [memory.geoStalkingMetaSecurityAnswer, memory.geoStalkingVisualSecurityAnswer]) {
        if (answer) expect(serializedConfig).to.not.include(`"${answer}"`)
      }
    }
  })
})
