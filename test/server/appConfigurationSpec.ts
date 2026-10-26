/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import config from 'config'
import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import { retrieveAppConfiguration, clientConfigurationAllowlist } from '../../routes/appConfiguration'
const expect = chai.expect
chai.use(sinonChai)

function leafPaths (obj: Record<string, any>, prefix = ''): string[] {
  return Object.entries(obj).flatMap(([key, value]) =>
    value !== null && typeof value === 'object' && !Array.isArray(value)
      ? leafPaths(value, `${prefix}${key}.`)
      : [`${prefix}${key}`])
}

describe('appConfiguration', () => {
  let req: any
  let res: any

  beforeEach(() => {
    req = {}
    res = { json: sinon.spy() }
    retrieveAppConfiguration()(req, res)
  })

  it('should return configuration object', () => {
    // eslint-disable-next-line @typescript-eslint/no-unused-expressions
    expect(res.json).to.have.been.calledOnce
    const returnedConfig = res.json.firstCall.args[0].config
    // eslint-disable-next-line @typescript-eslint/no-unused-expressions
    expect(returnedConfig.application).to.exist
  })

  it('should not expose chatBot.llmApiUrl', () => {
    const returnedConfig = res.json.firstCall.args[0].config
    expect(returnedConfig.application.chatBot).to.not.have.property('llmApiUrl')
  })

  it('should only expose allowlisted settings', () => {
    const returnedConfig = res.json.firstCall.args[0].config
    for (const path of leafPaths(returnedConfig)) {
      expect(clientConfigurationAllowlist).to.include(path)
    }
    expect(returnedConfig).to.not.have.any.keys('server', 'products', 'memories')
    expect(returnedConfig.application).to.not.have.any.keys('customMetricsPrefix', 'securityTxt', 'easterEggPlanet')
    expect(returnedConfig.challenges).to.not.have.any.keys('csafHashValue', 'xssBonusPayload', 'safetyMode', 'metricsIgnoredUserAgents')
    expect(returnedConfig.ctf).to.not.have.property('countryMapping')
  })

  it('should expose the settings the frontend relies on', () => {
    const returnedConfig = res.json.firstCall.args[0].config
    expect(returnedConfig.application.name).to.equal(config.get('application.name'))
    expect(returnedConfig.application.domain).to.equal(config.get('application.domain'))
    expect(returnedConfig.application.chatBot).to.have.all.keys('name', 'avatar', 'sampleQuestions')
    expect(returnedConfig.hackingInstructor).to.have.all.keys('isEnabled', 'hintPlaybackSpeed')
    expect(returnedConfig.ctf).to.have.property('showFlagsInNotifications')
  })
})
