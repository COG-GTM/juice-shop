/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import config from 'config'

import { themes } from '../views/themes/themes'
import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'

function favicon () {
  return utils.extractFilename(config.get('application.favicon'))
}

export function getUserProfile () {
  return async (req: Request, res: Response, next: NextFunction) => {
    let fn
    try {
      const pug = (await import('pug')).default
      fn = pug.compileFile('views/userProfile.pug', { cache: true })
    } catch (err) {
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

    const themeKey = config.get<string>('application.theme') as keyof typeof themes
    const theme = themes[themeKey] || themes['bluegrey-lightgreen']

    try {
      const CSP = `img-src 'self' ${user.profileImage}; script-src 'self' 'unsafe-eval'`

      res.set({
        'Content-Security-Policy': CSP
      })

      res.send(fn({
        username: user.username,
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
