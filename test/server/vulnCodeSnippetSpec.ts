/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import { type Challenge } from 'data/types'
import { challenges } from '../../data/datacache'
import { ChallengeModel } from '../../models/challenge'
import { serveCodeSnippet, checkVulnLines, retrieveCodeSnippet, retrieveChallengesWithCodeSnippet } from '../../routes/vulnCodeSnippet'

const expect = chai.expect
chai.use(sinonChai)

describe('vulnCodeSnippet routes', () => {
  const originalChallenges = { ...challenges }

  after(() => {
    for (const key of Object.keys(challenges)) {
      delete challenges[key]
    }
    Object.assign(challenges, originalChallenges)
  })

  let req: any
  let res: any
  let next: any

  beforeEach(() => {
    res = { json: sinon.spy(), status: sinon.stub(), __: sinon.stub().callsFake((text: string, params?: Record<string, string>) => params ? `${text} ${JSON.stringify(params)}` : text) }
    res.status.returns(res)
    next = sinon.spy()
  })

  it('should list challenges with code snippets', async () => {
    const keys = await retrieveChallengesWithCodeSnippet()

    expect(keys).to.include('loginAdminChallenge')
  })

  it('should return null for challenges without code snippet', async () => {
    expect(await retrieveCodeSnippet('doesNotExistChallenge')).to.equal(null)
  })

  describe('serveCodeSnippet', () => {
    it('should serve snippet of existing coding challenge', async () => {
      req = { params: { challenge: 'loginAdminChallenge' } }

      await serveCodeSnippet()(req, res, next)

      expect(res.status).to.have.been.calledWith(200)
      expect(res.json).to.have.been.calledWith({ snippet: sinon.match('SELECT * FROM Users WHERE email') })
    })

    it('should respond with 404 for unknown challenge', async () => {
      req = { params: { challenge: 'doesNotExistChallenge' } }

      await serveCodeSnippet()(req, res, next)

      expect(res.status).to.have.been.calledWith(404)
      expect(res.json).to.have.been.calledWith({ status: 'error', error: 'No code challenge for challenge key: doesNotExistChallenge' })
    })
  })

  describe('checkVulnLines', () => {
    it('should respond with 404 for unknown challenge', async () => {
      req = { body: { key: 'doesNotExistChallenge', selectedLines: [1] } }

      await checkVulnLines()(req, res, next)

      expect(res.status).to.have.been.calledWith(404)
      expect(res.json).to.have.been.calledWith({ status: 'error', error: 'No code challenge for challenge key: doesNotExistChallenge' })
    })

    it('should return negative verdict with next hint for wrongly selected lines', async () => {
      req = { body: { key: 'redirectChallenge', selectedLines: [] } }

      await checkVulnLines()(req, res, next)
      await checkVulnLines()(req, res, next)

      expect(res.status).to.have.been.calledWith(200)
      expect(res.json.firstCall).to.have.been.calledWith({ verdict: false, hint: undefined })
      expect(res.json.secondCall).to.have.been.calledWith({ verdict: false, hint: 'You should take a close look at how this code checks for allowed vs. forbidded URLs to redirect to.' })
    })

    it('should reveal vulnerable line after all hints were given', async () => {
      req = { body: { key: 'redirectChallenge', selectedLines: [] } }

      for (let i = 0; i < 4; i++) {
        await checkVulnLines()(req, res, next)
      }

      expect(res.json.lastCall.args[0].verdict).to.equal(false)
      expect(res.json.lastCall.args[0].hint).to.match(/^Line \{\{vulnLine\}\} is responsible for this vulnerability/)
    })

    it('should return positive verdict and solve "Find It" phase for correctly selected lines', async () => {
      const key = 'redirectCryptoCurrencyChallenge'
      const snippet = await retrieveCodeSnippet(key)
      challenges[key] = { key, name: 'Outdated Allowlist' } as unknown as Challenge
      const update = sinon.stub(ChallengeModel, 'update').resolves([1] as any)
      req = { body: { key, selectedLines: snippet?.vulnLines } }

      try {
        await checkVulnLines()(req, res, next)
      } finally {
        update.restore()
      }

      expect(update).to.have.been.calledWith({ codingChallengeStatus: 1 }, sinon.match({ where: sinon.match({ key }) }))
      expect(res.json).to.have.been.calledWith({ verdict: true })
    })
  })
})
