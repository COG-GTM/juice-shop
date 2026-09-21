/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type HttpEvent, type HttpHandler, type HttpInterceptor, type HttpRequest } from '@angular/common/http'
import { Injectable } from '@angular/core'
import { type Observable } from 'rxjs'

import { environment } from '../../environments/environment'

function originOf (url: string): string | null {
  try {
    return new URL(url, window.location.href).origin
  } catch {
    return null
  }
}

function isApplicationRequest (url: string): boolean {
  const target = originOf(url)
  return target !== null && (target === window.location.origin || target === originOf(environment.hostServer))
}

@Injectable()
export class RequestInterceptor implements HttpInterceptor {
  intercept (req: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
    const token = localStorage.getItem('token')
    if (token && isApplicationRequest(req.url)) {
      req = req.clone({
        setHeaders: {
          Authorization: `Bearer ${token}`
        }
      })
    }
    return next.handle(req)
  }
}
