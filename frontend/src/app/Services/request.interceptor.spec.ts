/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing'
import { HTTP_INTERCEPTORS, HttpClient, provideHttpClient, withInterceptorsFromDi } from '@angular/common/http'
import { TestBed } from '@angular/core/testing'
import { Router } from '@angular/router'
import { RequestInterceptor, sessionEndedMessage } from './request.interceptor'
import { UserService } from './user.service'

describe('RequestInterceptor', () => {
    let http: HttpClient
    let httpMock: HttpTestingController
    let router: { navigate: ReturnType<typeof vi.fn> }
    let userService: { isLoggedIn: { next: ReturnType<typeof vi.fn> } }

    beforeEach(() => {
        router = { navigate: vi.fn().mockResolvedValue(true) }
        userService = { isLoggedIn: { next: vi.fn() } }
        TestBed.configureTestingModule({
            providers: [
                { provide: HTTP_INTERCEPTORS, useClass: RequestInterceptor, multi: true },
                { provide: Router, useValue: router },
                { provide: UserService, useValue: userService },
                provideHttpClient(withInterceptorsFromDi()),
                provideHttpClientTesting()
            ]
        })
        http = TestBed.inject(HttpClient)
        httpMock = TestBed.inject(HttpTestingController)
        localStorage.setItem('token', 'old')
    })

    afterEach(() => {
        localStorage.removeItem('token')
        httpMock.verify()
    })

    it('should send the stored token as bearer', () => {
        http.get('/rest/wallet/balance').subscribe()
        const req = httpMock.expectOne('/rest/wallet/balance')
        expect(req.request.headers.get('Authorization')).toBe('Bearer old')
        req.flush({})
    })

    it('should end the local session and go to login when the server reports the session has ended', () => {
        let error: any
        http.get('/rest/wallet/balance').subscribe({ error: (err) => (error = err) })
        httpMock.expectOne('/rest/wallet/balance').flush({ status: 'error', message: sessionEndedMessage }, { status: 401, statusText: 'Unauthorized' })

        expect(error.status).toBe(401)
        expect(localStorage.getItem('token')).toBeNull()
        expect(userService.isLoggedIn.next).toHaveBeenCalledWith(false)
        expect(router.navigate).toHaveBeenCalledWith(['/login'])
    })

    it('should keep the session on other 401 responses', () => {
        http.get('/rest/user/change-password').subscribe({ error: () => {} })
        httpMock.expectOne('/rest/user/change-password').flush('Current password is not correct.', { status: 401, statusText: 'Unauthorized' })

        expect(localStorage.getItem('token')).toBe('old')
        expect(router.navigate).not.toHaveBeenCalled()
    })

    it('should keep a newer token stored while the old request was in flight', () => {
        http.get('/rest/wallet/balance').subscribe({ error: () => {} })
        localStorage.setItem('token', 'new')
        httpMock.expectOne('/rest/wallet/balance').flush({ message: sessionEndedMessage }, { status: 401, statusText: 'Unauthorized' })

        expect(localStorage.getItem('token')).toBe('new')
        expect(router.navigate).not.toHaveBeenCalled()
    })
})
