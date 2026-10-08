/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import logger from '../lib/logger'
import { fetchProfileImage, type ProfileImage, ProfileImageFetchError } from '../lib/profileImageFetch'

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        let image: ProfileImage | undefined
        try {
          image = await fetchProfileImage(url)
        } catch (error) {
          const reason = error instanceof ProfileImageFetchError ? error.message : 'request failed'
          logger.warn(`Error retrieving user profile image: ${reason}; profile image left unchanged`)
        }
        if (image) {
          try {
            const fileName = `${loggedInUser.data.id}.${image.extension}`
            await fs.promises.writeFile(`frontend/dist/frontend/assets/public/images/uploads/${fileName}`, image.data)
            const user = await UserModel.findByPk(loggedInUser.data.id)
            await user?.update({ profileImage: `/assets/public/images/uploads/${fileName}` })
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
