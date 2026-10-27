/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import * as Prometheus from 'prom-client'
import { ChallengeModel } from '../../models/challenge'
import { UserModel } from '../../models/user'
import { WalletModel } from '../../models/wallet'
import { FeedbackModel } from '../../models/feedback'
import { ComplaintModel } from '../../models/complaint'
import { ordersCollection, reviewsCollection } from '../../data/mongodb'
import { retrieveChallengesWithCodeSnippet } from '../../routes/vulnCodeSnippet'
import { observeMetrics } from '../../routes/metrics'

const expect = chai.expect
chai.use(sinonChai)

describe('metrics', () => {
  const register = Prometheus.register
  let preexistingMetrics: string[]
  let metrics: ReturnType<typeof observeMetrics>
  let challengeCount: sinon.SinonStub
  let userCount: sinon.SinonStub
  let walletSum: sinon.SinonStub
  let feedbackCount: sinon.SinonStub
  let complaintCount: sinon.SinonStub
  let orderCount: sinon.SinonStub
  let reviewCount: sinon.SinonStub

  before(() => {
    preexistingMetrics = register.getMetricsAsArray().map(({ name }) => name)
    metrics = observeMetrics()
  })

  after(() => {
    for (const { name } of register.getMetricsAsArray()) {
      if (!preexistingMetrics.includes(name)) register.removeSingleMetric(name)
    }
  })

  beforeEach(() => {
    challengeCount = sinon.stub(ChallengeModel, 'count').resolves([
      { codingChallengeStatus: 0, count: 5 },
      { codingChallengeStatus: 1, count: 2 },
      { codingChallengeStatus: 2, count: 3 },
      { codingChallengeStatus: null, count: 1 }
    ] as any)
    userCount = sinon.stub(UserModel, 'count').resolves([
      { role: 'customer', count: 4 },
      { role: 'deluxe', count: 2 },
      { role: 'admin', count: 1 },
      { role: 'accounting', count: 1 }
    ] as any)
    walletSum = sinon.stub(WalletModel, 'sum').resolves(1234 as any)
    feedbackCount = sinon.stub(FeedbackModel, 'count').resolves(7 as any)
    complaintCount = sinon.stub(ComplaintModel, 'count').resolves(3 as any)
    orderCount = sinon.stub(ordersCollection, 'count').resolves(9)
    reviewCount = sinon.stub(reviewsCollection, 'count').resolves(11)
  })

  afterEach(() => {
    sinon.restore()
  })

  const allQueries = () => [challengeCount, userCount, walletSum, feedbackCount, complaintCount, orderCount, reviewCount]

  it('should not query any data store without a scrape', async () => {
    expect(metrics.updateLoop()).to.equal(undefined)
    await new Promise(resolve => setTimeout(resolve, 50))

    for (const query of allQueries()) {
      expect(query).to.have.callCount(0)
    }
  })

  it('should issue one grouped query per model and one query per other source on each scrape', async () => {
    await register.metrics()

    expect(challengeCount).to.have.been.calledOnceWithExactly({ group: ['codingChallengeStatus'] })
    expect(userCount).to.have.been.calledOnceWithExactly({ group: ['role'] })
    for (const query of allQueries()) {
      expect(query).to.have.callCount(1)
    }

    await register.metrics()
    for (const query of allQueries()) {
      expect(query).to.have.callCount(2)
    }
  })

  it('should share one refresh between concurrent scrapes', async () => {
    await Promise.all([register.metrics(), register.metrics()])

    for (const query of allQueries()) {
      expect(query).to.have.callCount(1)
    }
  })

  it('should derive coding challenge progress from the grouped status counts', async () => {
    const codingChallenges = await retrieveChallengesWithCodeSnippet()
    const text = await register.metrics()

    expect(text).to.match(/^juiceshop_coding_challenges_progress{phase="find it",app="juiceshop"} 2$/m)
    expect(text).to.match(/^juiceshop_coding_challenges_progress{phase="fix it",app="juiceshop"} 3$/m)
    expect(text).to.include(`juiceshop_coding_challenges_progress{phase="unsolved",app="juiceshop"} ${codingChallenges.length - 5}\n`)
  })

  it('should derive user counts from the grouped role counts', async () => {
    const text = await register.metrics()

    expect(text).to.match(/^juiceshop_users_registered{type="standard",app="juiceshop"} 4$/m)
    expect(text).to.match(/^juiceshop_users_registered{type="deluxe",app="juiceshop"} 2$/m)
    expect(text).to.match(/^juiceshop_users_registered_total{app="juiceshop"} 8$/m)
  })

  it('should report the remaining counts on scrape', async () => {
    const text = await register.metrics()

    expect(text).to.match(/^juiceshop_wallet_balance_total{app="juiceshop"} 1234$/m)
    expect(text).to.match(/^juiceshop_orders_placed_total{app="juiceshop"} 9$/m)
    expect(text).to.match(/^juiceshop_user_social_interactions{type="review",app="juiceshop"} 11$/m)
    expect(text).to.match(/^juiceshop_user_social_interactions{type="feedback",app="juiceshop"} 7$/m)
    expect(text).to.match(/^juiceshop_user_social_interactions{type="complaint",app="juiceshop"} 3$/m)
    expect(text).to.match(/^juiceshop_version_info{version="[0-9]+.[0-9]+.[0-9]+(-SNAPSHOT)?",major="[0-9]+",minor="[0-9]+",patch="[0-9]+",app="juiceshop"} 1$/m)
  })
})
