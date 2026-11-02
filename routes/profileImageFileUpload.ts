/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs/promises'
import { type Request, type Response, type NextFunction } from 'express'
import fileType from 'file-type'

import logger from '../lib/logger'
import * as utils from '../lib/utils'
import { UserModel } from '../models/user'
import * as security from '../lib/insecurity'
import { profileImageUploadPath, toProfileImageUserId } from '../lib/profileImageUpload'

export function profileImageFileUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const file = req.file
    const buffer = file?.buffer
    if (buffer === undefined) {
      res.status(500)
      next(new Error('Illegal file type'))
      return
    }
    const uploadedFileType = await fileType.fromBuffer(buffer)
    if (uploadedFileType === undefined) {
      res.status(500)
      next(new Error('Illegal file type'))
      return
    }
    if (uploadedFileType === null || !utils.startsWith(uploadedFileType.mime, 'image')) {
      res.status(415)
      next(new Error(`Profile image upload does not accept this file type${uploadedFileType ? (': ' + uploadedFileType.mime) : '.'}`))
      return
    }
    const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
    if (!loggedInUser) {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
      return
    }

    const userId = toProfileImageUserId(loggedInUser.data?.id)
    const filePath = userId === undefined ? undefined : profileImageUploadPath(userId, uploadedFileType.ext)
    if (userId === undefined || filePath === undefined) {
      res.status(400)
      next(new Error('Invalid user id in session'))
      return
    }

    try {
      await fs.writeFile(filePath, buffer)
    } catch (err) {
      logger.warn('Error writing file: ' + (err instanceof Error ? err.message : String(err)))
    }

    try {
      const user = await UserModel.findByPk(userId)
      if (user != null) {
        await user.update({ profileImage: `assets/public/images/uploads/${userId}.${uploadedFileType.ext}` })
      }
    } catch (error) {
      next(error)
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
