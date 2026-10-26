/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs/promises'
import { type Request, type Response, type NextFunction } from 'express'
import fileType from 'file-type'
import { MemoryModel } from '../models/memory'
import { UserModel } from '../models/user'

const allowedImageTypes = ['image/png', 'image/jpeg']

export function ensureMemoryImageContent () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const filePath = req.file?.path
    const detectedType = filePath ? await fileType.fromFile(filePath) : undefined
    if (detectedType && allowedImageTypes.includes(detectedType.mime)) {
      next()
      return
    }
    if (filePath) {
      await fs.rm(filePath, { force: true })
    }
    res.status(400).json({ status: 'error', message: 'Uploaded file is not a PNG or JPEG image' })
  }
}

export function addMemory () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const record = {
      caption: req.body.caption,
      imagePath: 'assets/public/images/uploads/' + req.file?.filename,
      UserId: req.body.UserId
    }
    const memory = await MemoryModel.create(record)
    res.status(200).json({ status: 'success', data: memory })
  }
}

export function getMemories () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const memories = await MemoryModel.findAll({ include: [UserModel] })
    res.status(200).json({ status: 'success', data: memories })
  }
}
