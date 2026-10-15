/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import { retrieveAppConfiguration } from '../../routes/appConfiguration'
const expect = chai.expect
chai.use(sinonChai)

describe('appConfiguration', () => {
  let req: any
  let res: any

  it('should return configuration object', () => {
    req = {}
    res = { json: sinon.spy() }

    retrieveAppConfiguration()(req, res)
    // eslint-disable-next-line @typescript-eslint/no-unused-expressions
    expect(res.json).to.have.been.calledOnce
    const returnedConfig = res.json.firstCall.args[0].config
    // eslint-disable-next-line @typescript-eslint/no-unused-expressions
    expect(returnedConfig.application).to.exist
  })

  it('should not expose chatBot.llmApiUrl', () => {
    req = {}
    res = { json: sinon.spy() }

    retrieveAppConfiguration()(req, res)
    const returnedConfig = res.json.firstCall.args[0].config
    // eslint-disable-next-line @typescript-eslint/no-unused-expressions
    expect(returnedConfig.application.chatBot).to.exist
    expect(returnedConfig.application.chatBot).to.not.have.property('llmApiUrl')
  })

  it('should only expose allowlisted client settings', () => {
    req = {}
    res = { json: sinon.spy() }

    retrieveAppConfiguration()(req, res)
    const returnedConfig = res.json.firstCall.args[0].config
    expect(returnedConfig).to.have.all.keys('application', 'challenges', 'hackingInstructor', 'ctf')
    expect(returnedConfig).to.not.have.any.keys('server', 'products', 'memories')
    expect(returnedConfig.application).to.not.have.any.keys('customMetricsPrefix', 'cookieConsent', 'securityTxt', 'promotion', 'easterEggPlanet')
    expect(returnedConfig.application.chatBot).to.have.all.keys('name', 'avatar', 'sampleQuestions')
    expect(returnedConfig.challenges).to.not.have.any.keys('csafHashValue', 'xssBonusPayload', 'overwriteUrlForProductTamperingChallenge', 'safetyMode', 'metricsIgnoredUserAgents')
    expect(returnedConfig.ctf).to.not.have.property('countryMapping')
  })

  it('should expose settings the client relies on', () => {
    req = {}
    res = { json: sinon.spy() }

    retrieveAppConfiguration()(req, res)
    const returnedConfig = res.json.firstCall.args[0].config
    expect(returnedConfig.application.name).to.equal('OWASP Juice Shop')
    expect(returnedConfig.application.domain).to.equal('juice-sh.op')
    expect(returnedConfig.application.social).to.have.property('twitterUrl')
    expect(returnedConfig.application.googleOauth).to.have.all.keys('clientId', 'authorizedRedirects')
    expect(returnedConfig.hackingInstructor).to.have.all.keys('isEnabled', 'hintPlaybackSpeed')
    expect(returnedConfig.ctf).to.have.property('showFlagsInNotifications')
  })
})
