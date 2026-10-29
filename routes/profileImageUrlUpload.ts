/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'
import { profileImageUploadPath } from './profileImageFileUpload'

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        if (profileImageUploadPath(loggedInUser.data.id, 'jpg') === null) {
          res.status(400)
          next(new Error('Invalid user id'))
          return
        }
        const userId = Number(loggedInUser.data.id)
        try {
          const response = await fetch(url)
          if (!response.ok || !response.body) {
            throw new Error('url returned a non-OK status code or an empty body')
          }
          const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg'
          const filePath = profileImageUploadPath(userId, ext)
          const user = await UserModel.findByPk(userId)
          if (filePath === null || user == null) {
            throw new Error('unknown user')
          }
          const fileStream = fs.createWriteStream(filePath, { flags: 'w' })
          await finished(Readable.fromWeb(response.body as any).pipe(fileStream))
          await user.update({ profileImage: `/assets/public/images/uploads/${userId}.${ext}` })
        } catch (error) {
          try {
            const user = await UserModel.findByPk(userId)
            await user?.update({ profileImage: url })
            logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(error)}; using image link directly`)
          } catch (error) {
            next(error)
            return
          }
        }
      } else {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        return
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
