/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { retrieveChallengesWithCodeSnippet } from './vulnCodeSnippet'
import { type Request, type Response, type NextFunction } from 'express'
import { ChallengeModel } from '../models/challenge'
import { UserModel } from '../models/user'
import { WalletModel } from '../models/wallet'
import { FeedbackModel } from '../models/feedback'
import { ComplaintModel } from '../models/complaint'
import * as challengeUtils from '../lib/challengeUtils'
import logger from '../lib/logger'
import config from 'config'
import * as utils from '../lib/utils'
import { totalCheatScore } from '../lib/antiCheat'
import * as accuracy from '../lib/accuracy'
import { reviewsCollection, ordersCollection } from '../data/mongodb'
import { challenges } from '../data/datacache'
import * as Prometheus from 'prom-client'
import onFinished from 'on-finished'

const register = Prometheus.register

const fileUploadsCountMetric = new Prometheus.Counter({
  name: 'file_uploads_count',
  help: 'Total number of successful file uploads grouped by file type.',
  labelNames: ['file_type']
})

const fileUploadErrorsMetric = new Prometheus.Counter({
  name: 'file_upload_errors',
  help: 'Total number of failed file uploads grouped by file type.',
  labelNames: ['file_type']
})

const httpRequestsMetric = new Prometheus.Counter({
  name: 'http_requests_count',
  help: 'Total HTTP request count grouped by status code.',
  labelNames: ['status_code']
})

export function observeRequestMetricsMiddleware () {
  return (req: Request, res: Response, next: NextFunction) => {
    onFinished(res, () => {
      const statusCode = `${Math.floor(res.statusCode / 100)}XX`
      httpRequestsMetric.labels(statusCode).inc()
    })
    next()
  }
}

export function observeFileUploadMetricsMiddleware () {
  return ({ file }: Request, res: Response, next: NextFunction) => {
    onFinished(res, () => {
      if (file != null) {
        res.statusCode < 400 ? fileUploadsCountMetric.labels(file.mimetype).inc() : fileUploadErrorsMetric.labels(file.mimetype).inc()
      }
    })
    next()
  }
}

export function serveMetrics () {
  return async (req: Request, res: Response, next: NextFunction) => {
    challengeUtils.solveIf(challenges.exposedMetricsChallenge, () => {
      const userAgent = req.headers['user-agent'] ?? ''
      const ignoredUserAgents = config.get<string[]>('challenges.metricsIgnoredUserAgents')
      return !ignoredUserAgents.some((ignoredUserAgent) => userAgent.includes(ignoredUserAgent))
    })
    res.set('Content-Type', register.contentType)
    res.end(await register.metrics())
  }
}

export function observeMetrics () {
  const app = config.get<string>('application.customMetricsPrefix')
  Prometheus.collectDefaultMetrics({})
  register.setDefaultLabels({ app })

  // All gauges of one scrape share a single refresh, so nothing is queried unless /metrics is requested
  let pendingUpdate: Promise<void> | undefined
  async function collect () {
    pendingUpdate ??= updateMetrics()
      .catch((e: unknown) => { logger.warn('Error during metrics update: ' + utils.getErrorMessage(e)) })
      .finally(() => { pendingUpdate = undefined })
    await pendingUpdate
  }

  const versionMetrics = new Prometheus.Gauge({
    collect,
    name: `${app}_version_info`,
    help: `Release version of ${config.get<string>('application.name')}.`,
    labelNames: ['version', 'major', 'minor', 'patch']
  })

  const challengeSolvedMetrics = new Prometheus.Gauge({
    collect,
    name: `${app}_challenges_solved`,
    help: 'Number of solved challenges grouped by difficulty and category.',
    labelNames: ['difficulty', 'category']
  })

  const challengeTotalMetrics = new Prometheus.Gauge({
    collect,
    name: `${app}_challenges_total`,
    help: 'Total number of challenges grouped by difficulty and category.',
    labelNames: ['difficulty', 'category']
  })

  const codingChallengesProgressMetrics = new Prometheus.Gauge({
    collect,
    name: `${app}_coding_challenges_progress`,
    help: 'Number of coding challenges grouped by progression phase.',
    labelNames: ['phase']
  })

  const cheatScoreMetrics = new Prometheus.Gauge({
    collect,
    name: `${app}_cheat_score`,
    help: 'Overall probability that any hacking or coding challenges were solved by cheating.'
  })

  const accuracyMetrics = new Prometheus.Gauge({
    collect,
    name: `${app}_coding_challenges_accuracy`,
    help: 'Overall accuracy while solving coding challenges grouped by phase.',
    labelNames: ['phase']
  })

  const orderMetrics = new Prometheus.Gauge({
    collect,
    name: `${app}_orders_placed_total`,
    help: `Number of orders placed in ${config.get<string>('application.name')}.`
  })

  const userMetrics = new Prometheus.Gauge({
    collect,
    name: `${app}_users_registered`,
    help: 'Number of registered users grouped by customer type.',
    labelNames: ['type']
  })

  const userTotalMetrics = new Prometheus.Gauge({
    collect,
    name: `${app}_users_registered_total`,
    help: 'Total number of registered users.'
  })

  const walletMetrics = new Prometheus.Gauge({
    collect,
    name: `${app}_wallet_balance_total`,
    help: 'Total balance of all users\' digital wallets.'
  })

  const interactionsMetrics = new Prometheus.Gauge({
    collect,
    name: `${app}_user_social_interactions`,
    help: 'Number of social interactions with users grouped by type.',
    labelNames: ['type']
  })

  const updateMetrics = async () => {
    const version = utils.version()
    const { major, minor, patch } = version.match(/(?<major>\d+).(?<minor>\d+).(?<patch>\d+)/).groups
    versionMetrics.set({ version, major, minor, patch }, 1)

    const challengeStatuses = new Map()
    const challengeCount = new Map()

    for (const { difficulty, category, solved } of Object.values<ChallengeModel>(challenges)) {
      const key = `${difficulty}:${category}`

      // Increment by one if solved, when not solved increment by 0. This ensures that even unsolved challenges are set to , instead of not being set at all
      challengeStatuses.set(key, (challengeStatuses.get(key) || 0) + (solved ? 1 : 0))
      challengeCount.set(key, (challengeCount.get(key) || 0) + 1)
    }

    for (const key of challengeStatuses.keys()) {
      const [difficulty, category] = key.split(':', 2)

      challengeSolvedMetrics.set({ difficulty, category }, challengeStatuses.get(key))
      challengeTotalMetrics.set({ difficulty, category }, challengeCount.get(key))
    }

    const [codingChallenges, codingChallengeStatusCounts, orderCount, reviewCount, userRoleCounts, totalBalance, feedbackCount, complaintCount] = await Promise.all([
      retrieveChallengesWithCodeSnippet(),
      ChallengeModel.count({ group: ['codingChallengeStatus'] }),
      ordersCollection.count({}),
      reviewsCollection.count({}),
      UserModel.count({ group: ['role'] }),
      WalletModel.sum('balance'),
      FeedbackModel.count(),
      ComplaintModel.count()
    ])

    let findItCount = 0
    let fixItCount = 0
    let solvedCount = 0
    for (const { codingChallengeStatus, count } of codingChallengeStatusCounts) {
      if (codingChallengeStatus === 1) findItCount += count
      if (codingChallengeStatus === 2) fixItCount += count
      if (codingChallengeStatus != null && codingChallengeStatus !== 0) solvedCount += count
    }

    let customerCount = 0
    let deluxeCount = 0
    let totalUserCount = 0
    for (const { role, count } of userRoleCounts) {
      if (role === 'customer') customerCount += count
      if (role === 'deluxe') deluxeCount += count
      totalUserCount += count
    }

    codingChallengesProgressMetrics.set({ phase: 'find it' }, findItCount)
    codingChallengesProgressMetrics.set({ phase: 'fix it' }, fixItCount)
    codingChallengesProgressMetrics.set({ phase: 'unsolved' }, codingChallenges.length - solvedCount)

    cheatScoreMetrics.set(totalCheatScore())
    accuracyMetrics.set({ phase: 'find it' }, accuracy.totalFindItAccuracy())
    accuracyMetrics.set({ phase: 'fix it' }, accuracy.totalFixItAccuracy())

    if (orderCount) orderMetrics.set(orderCount)
    if (reviewCount) interactionsMetrics.set({ type: 'review' }, reviewCount)
    if (customerCount) userMetrics.set({ type: 'standard' }, customerCount)
    if (deluxeCount) userMetrics.set({ type: 'deluxe' }, deluxeCount)
    if (totalUserCount) userTotalMetrics.set(totalUserCount)
    if (totalBalance) walletMetrics.set(totalBalance)
    if (feedbackCount) interactionsMetrics.set({ type: 'feedback' }, feedbackCount)
    if (complaintCount) interactionsMetrics.set({ type: 'complaint' }, complaintCount)
  }

  // Kept for server.ts compatibility: metrics are now refreshed on scrape instead of on a timer
  const updateLoop = (): NodeJS.Timeout | undefined => undefined

  return {
    register,
    updateLoop
  }
}
