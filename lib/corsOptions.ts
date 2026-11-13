/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import config from 'config'
import { type CorsOptions } from 'cors'

export function corsAllowedOrigins (env: NodeJS.ProcessEnv = process.env): string[] {
  const origins = env.CORS_ALLOWED_ORIGINS ?? `${config.get<string>('server.baseUrl')},http://localhost:4200,http://127.0.0.1:4200`
  return origins.split(',').map(origin => origin.trim().replace(/\/+$/, '')).filter(origin => origin !== '' && origin !== '*')
}

export function corsOptions (allowedOrigins: string[] = corsAllowedOrigins()): CorsOptions {
  return {
    origin: (origin, callback) => {
      callback(null, origin !== undefined && allowedOrigins.includes(origin))
    }
  }
}
