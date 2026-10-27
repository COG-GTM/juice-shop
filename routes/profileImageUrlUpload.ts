/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'
import { fetchProfileImage } from '../lib/profileImageFetch'

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        if (typeof url === 'string' && url.includes('solve/challenges/server-side')) req.app.locals.abused_ssrf_bug = true
        try {
          const image = await fetchProfileImage(url)
          const fileName = `${loggedInUser.data.id}.${image.extension}`
          await fs.promises.writeFile(`frontend/dist/frontend/assets/public/images/uploads/${fileName}`, image.data)
          const user = await UserModel.findByPk(loggedInUser.data.id)
          await user?.update({ profileImage: `/assets/public/images/uploads/${fileName}` })
        } catch (error) {
          logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(error).replace(/[\r\n]+/g, ' ')}; keeping current profile image`)
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
