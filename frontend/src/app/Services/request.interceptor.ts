/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type HttpErrorResponse, type HttpEvent, type HttpHandler, type HttpInterceptor, type HttpRequest } from '@angular/common/http'
import { Injectable, Injector, inject } from '@angular/core'
import { Router } from '@angular/router'
import { type Observable, catchError, throwError } from 'rxjs'
import { UserService } from './user.service'

export const sessionEndedMessage = 'Session has ended. Please log in again.'

@Injectable()
export class RequestInterceptor implements HttpInterceptor {
  private readonly injector = inject(Injector)

  intercept (req: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
    const token = localStorage.getItem('token')
    if (token) {
      req = req.clone({
        setHeaders: {
          Authorization: `Bearer ${token}`
        }
      })
    }
    if (localStorage.getItem('email')) {
      req = req.clone({
        setHeaders: {
          'X-User-Email': String(localStorage.getItem('email'))
        }
      })
    }
    return next.handle(req).pipe(catchError((err: HttpErrorResponse) => {
      if (token && err?.status === 401 && err.error?.message === sessionEndedMessage && localStorage.getItem('token') === token) {
        this.endSession(token)
      }
      return throwError(() => err)
    }))
  }

  private endSession (token: string) {
    if (document.cookie.split('; ').includes(`token=${token}`)) {
      document.cookie = 'token=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/'
    }
    localStorage.removeItem('token')
    sessionStorage.removeItem('bid')
    sessionStorage.removeItem('itemTotal')
    this.injector.get(UserService).isLoggedIn.next(false)
    void this.injector.get(Router).navigate(['/login'])
  }
}
