/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs/promises'
import path from 'node:path'
import crypto from 'node:crypto'
import config from 'config'
import nodemailer, { type SendMailOptions, type Transporter } from 'nodemailer'

import { TOKEN_TTL_MS } from './passwordResetTokens'

export const outboxDir = path.resolve('mail/outbox')

let transporter: Transporter | undefined

function smtpTransporter (): Transporter | undefined {
  if (!process.env.SMTP_HOST) {
    return undefined
  }
  transporter ??= nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT ?? 587),
    secure: process.env.SMTP_SECURE === 'true',
    auth: process.env.SMTP_USER ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS } : undefined
  })
  return transporter
}

async function writeToOutbox (message: SendMailOptions) {
  const { message: raw } = await nodemailer.createTransport({ streamTransport: true, buffer: true }).sendMail(message)
  await fs.mkdir(outboxDir, { recursive: true, mode: 0o700 })
  await fs.writeFile(path.join(outboxDir, `${Date.now()}-${crypto.randomUUID()}.eml`), raw as Buffer, { mode: 0o600 })
}

export async function sendMail (message: SendMailOptions) {
  const from = process.env.SMTP_FROM ?? `no-reply@${config.get<string>('application.domain')}`
  const smtp = smtpTransporter()
  if (smtp) {
    await smtp.sendMail({ from, ...message })
  } else {
    await writeToOutbox({ from, ...message })
  }
}

export async function sendPasswordResetEmail (email: string, token: string) {
  await sendMail({
    to: email,
    subject: `${config.get<string>('application.name')} password reset`,
    text: `Use the following code to reset your password. It expires in ${TOKEN_TTL_MS / 60000} minutes and can only be used once.\n\n${token}\n\nIf you did not request a password reset, you can ignore this email.`
  })
}
