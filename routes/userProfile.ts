/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { AllHtmlEntities as Entities } from 'html-entities'
import config from 'config'

import * as challengeUtils from '../lib/challengeUtils'
import { themes } from '../views/themes/themes'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'

const entities = new Entities()

function favicon () {
  return utils.extractFilename(config.get('application.favicon'))
}

let compiledTemplate: Promise<(locals: Record<string, unknown>) => string> | undefined

async function getTemplate () {
  compiledTemplate ??= (async () => {
    const pug = (await import('pug')).default
    return pug.compileFile('views/userProfile.pug')
  })()
  return await compiledTemplate
}

export function getUserProfile () {
  return async (req: Request, res: Response, next: NextFunction) => {
    let fn: (locals: Record<string, unknown>) => string
    try {
      fn = await getTemplate()
    } catch (err) {
      compiledTemplate = undefined
      next(err)
      return
    }

    const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
    if (!loggedInUser) {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress)); return
    }

    let user: UserModel | null
    try {
      user = await UserModel.findByPk(loggedInUser.data.id)
    } catch (error) {
      next(error)
      return
    }

    if (!user) {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
      return
    }

    const username = user.username ?? ''
    const usernameXssEnabled = utils.isChallengeEnabled(challenges.usernameXssChallenge)

    const themeKey = config.get<string>('application.theme') as keyof typeof themes
    const theme = themes[themeKey] || themes['bluegrey-lightgreen']

    try {
      const CSP = `img-src 'self' ${user?.profileImage}; script-src 'self' 'unsafe-eval'`

      challengeUtils.solveIf(challenges.usernameXssChallenge, () => {
        return username && user?.profileImage.match(/;[ ]*script-src(.)*'unsafe-inline'/g) !== null && utils.contains(username, '<script>alert(`xss`)</script>')
      })

      res.set({
        'Content-Security-Policy': CSP
      })

      res.send(fn({
        username,
        usernameHtml: usernameXssEnabled ? username : entities.encode(username),
        email: user.email,
        profileImage: user.profileImage,
        emailHash: security.hash(user.email),
        title: config.get<string>('application.name'),
        favicon: favicon(),
        logo: utils.extractFilename(config.get('application.logo')),
        bgColor: theme.bgColor,
        textColor: theme.textColor,
        navColor: theme.navColor,
        primLight: theme.primLight,
        primDark: theme.primDark
      }))
    } catch (err) {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
    }
  }
}
