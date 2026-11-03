/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import config from 'config'
import { publicConfigKeys, retrieveAppConfiguration } from '../../routes/appConfiguration'
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

  it('should only return allow-listed configuration values', () => {
    req = {}
    res = { json: sinon.spy() }

    retrieveAppConfiguration()(req, res)
    const returnedConfig = res.json.firstCall.args[0].config

    expect(returnedConfig).to.not.have.property('memories')
    expect(returnedConfig).to.not.have.property('products')
    expect(returnedConfig).to.not.have.property('server')
    expect(returnedConfig.application.chatBot).to.not.have.property('model')
    expect(returnedConfig.application.chatBot).to.not.have.property('llmApiUrl')
    expect(returnedConfig.application.chatBot).to.not.have.property('llmMaxRetries')
    expect(returnedConfig.challenges).to.not.have.property('xssBonusPayload')
    expect(returnedConfig.challenges).to.not.have.property('csafHashValue')
    expect(returnedConfig.challenges).to.not.have.property('overwriteUrlForProductTamperingChallenge')
    expect(returnedConfig.challenges).to.not.have.property('metricsIgnoredUserAgents')
    expect(returnedConfig.ctf).to.not.have.property('countryMapping')
    expect(JSON.stringify(returnedConfig)).to.not.include('SecurityAnswer')
  })

  it('should include public configuration values used by the frontend', () => {
    req = {}
    res = { json: sinon.spy() }

    retrieveAppConfiguration()(req, res)
    const returnedConfig = res.json.firstCall.args[0].config

    expect(returnedConfig.application.name).to.equal(config.get('application.name'))
    expect(returnedConfig.application.social.twitterUrl).to.equal(config.get('application.social.twitterUrl'))
    expect(returnedConfig.application.chatBot.name).to.equal(config.get('application.chatBot.name'))
    expect(returnedConfig.hackingInstructor.isEnabled).to.equal(config.get('hackingInstructor.isEnabled'))
    expect(returnedConfig.challenges.codingChallengesEnabled).to.equal(config.get('challenges.codingChallengesEnabled'))
  })

  it('should only include allow-listed leaf paths', () => {
    req = {}
    res = { json: sinon.spy() }

    retrieveAppConfiguration()(req, res)
    const returnedConfig = res.json.firstCall.args[0].config
    const allowedKeys = new Set(publicConfigKeys)
    const authorizedRedirectsKey = 'application.googleOauth.authorizedRedirects'

    const inspectConfig = (value: unknown, path: string) => {
      if (path === authorizedRedirectsKey) {
        expect(allowedKeys.has(path)).to.equal(true)
        expect(Array.isArray(value)).to.equal(true)
        for (const redirect of value as Array<Record<string, unknown>>) {
          expect(Object.keys(redirect).every(key => ['uri', 'proxy'].includes(key))).to.equal(true)
        }
        return
      }

      if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
        if (path !== '') {
          expect(publicConfigKeys.some(key => key.startsWith(`${path}.`))).to.equal(true)
        }
        for (const [childKey, childValue] of Object.entries(value)) {
          inspectConfig(childValue, path === '' ? childKey : `${path}.${childKey}`)
        }
        return
      }

      expect(allowedKeys.has(path)).to.equal(true)
    }

    inspectConfig(returnedConfig, '')
  })
})
