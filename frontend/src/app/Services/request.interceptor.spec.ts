/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { HttpClient, HTTP_INTERCEPTORS, provideHttpClient, withInterceptorsFromDi } from '@angular/common/http'
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing'
import { TestBed } from '@angular/core/testing'

import { RequestInterceptor } from './request.interceptor'
import { environment } from '../../environments/environment'

describe('RequestInterceptor', () => {
  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(withInterceptorsFromDi()),
        provideHttpClientTesting(),
        { provide: HTTP_INTERCEPTORS, useClass: RequestInterceptor, multi: true }
      ]
    })
    localStorage.setItem('token', 'TOKEN')
    localStorage.setItem('email', 'admin@juice-sh.op')
  })

  afterEach(() => {
    localStorage.removeItem('token')
    localStorage.removeItem('email')
  })

  it('should attach the token to requests against the application itself', () => {
    const http = TestBed.inject(HttpClient)
    const httpMock = TestBed.inject(HttpTestingController)

    http.get('/rest/user/whoami').subscribe()
    const req = httpMock.expectOne('/rest/user/whoami')

    expect(req.request.headers.get('Authorization')).toBe('Bearer TOKEN')
    req.flush({})
    httpMock.verify()
  })

  it('should attach the token to requests against the configured host server', () => {
    const http = TestBed.inject(HttpClient)
    const httpMock = TestBed.inject(HttpTestingController)

    const url = `${environment.hostServer}/rest/user/whoami`
    http.get(url).subscribe()
    const req = httpMock.expectOne(url)

    expect(req.request.headers.get('Authorization')).toBe('Bearer TOKEN')
    req.flush({})
    httpMock.verify()
  })

  it('should not leak the token to third-party origins', () => {
    const http = TestBed.inject(HttpClient)
    const httpMock = TestBed.inject(HttpTestingController)

    const url = 'https://www.googleapis.com/oauth2/v1/userinfo'
    http.get(url).subscribe()
    const req = httpMock.expectOne(url)

    expect(req.request.headers.has('Authorization')).toBe(false)
    req.flush({})
    httpMock.verify()
  })

  it('should not send the email of the logged-in user as a header', () => {
    const http = TestBed.inject(HttpClient)
    const httpMock = TestBed.inject(HttpTestingController)

    http.get('/rest/user/whoami').subscribe()
    const req = httpMock.expectOne('/rest/user/whoami')

    expect(req.request.headers.has('X-User-Email')).toBe(false)
    req.flush({})
    httpMock.verify()
  })
})
