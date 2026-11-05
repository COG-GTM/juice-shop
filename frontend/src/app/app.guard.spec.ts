/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { TestBed } from '@angular/core/testing'
import { AccountingGuard, AdminGuard, DeluxeGuard, LoginGuard } from './app.guard'
import { provideHttpClientTesting } from '@angular/common/http/testing'
import { RouterTestingModule } from '@angular/router/testing'
import { ErrorPageComponent } from './error-page/error-page.component'
import { provideHttpClient, withInterceptorsFromDi } from '@angular/common/http'
import { endSession, startSession } from './Services/auth-session'

describe('LoginGuard', () => {
    beforeEach(() => {
        TestBed.configureTestingModule({
            imports: [RouterTestingModule.withRoutes([
                    { path: '403', component: ErrorPageComponent }
                ])],
            providers: [LoginGuard, provideHttpClient(withInterceptorsFromDi()), provideHttpClientTesting()]
        })
    })

    it('should be created', () => {
        const guard = TestBed.inject(LoginGuard)

        expect(guard).toBeTruthy()
    })

    it('should open for authenticated users', () => {
        const guard = TestBed.inject(LoginGuard)

        startSession('TOKEN')
        expect(guard.canActivate()).toBe(true)
    })

    it('should close for anonymous users', () => {
        const guard = TestBed.inject(LoginGuard)

        endSession()
        expect(guard.canActivate()).toBe(false)
    })

    it('should close when only a legacy localStorage token is present', () => {
        const guard = TestBed.inject(LoginGuard)

        endSession()
        localStorage.setItem('token', 'TOKEN')
        expect(guard.canActivate()).toBe(false)
        localStorage.removeItem('token')
    })

    it('returns only non-secret session claims from the login token', () => {
        const guard = TestBed.inject(LoginGuard)

        startSession('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJkYXRhIjp7ImlkIjoxLCJlbWFpbCI6ImFkbWluQGp1aWNlLXNoLm9wIiwicm9sZSI6ImFkbWluIiwicGFzc3dvcmQiOiIwMTkyMDIzYTdiYmQ3MzI1MDUxNmYwNjlkZjE4YjUwMCIsInRvdHBTZWNyZXQiOiJTRUNSRVQifSwiaWF0IjoxNTE2MjM5MDIyfQ.c2lnbmF0dXJl')
        expect(guard.tokenDecode()).toEqual({
            data: { id: 1, email: 'admin@juice-sh.op', role: 'admin' }
        })
        expect(localStorage.getItem('session')).not.toContain('SECRET')
        expect(localStorage.getItem('session')).not.toContain('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJkYXRhIjp7ImlkIjoxLCJlbWFpbCI6ImFkbWluQGp1aWNlLXNoLm9wIiwicm9sZSI6ImFkbWluIiwicGFzc3dvcmQiOiIwMTkyMDIzYTdiYmQ3MzI1MDUxNmYwNjlkZjE4YjUwMCIsInRvdHBTZWNyZXQiOiJTRUNSRVQifSwiaWF0IjoxNTE2MjM5MDIyfQ.c2lnbmF0dXJl')
    })

    it('returns nothing once the session has expired', () => {
        const guard = TestBed.inject(LoginGuard)

        startSession('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJkYXRhIjp7ImlkIjoxfSwiZXhwIjoxNTE2MjM5MDIyfQ.c2lnbmF0dXJl')
        expect(guard.tokenDecode()).toBeNull()
        expect(guard.canActivate()).toBe(false)
    })

    it('returns nothing without a session', () => {
        const guard = TestBed.inject(LoginGuard)

        endSession()
        expect(guard.tokenDecode()).toBeNull()
    })
})

describe('AdminGuard', () => {
    let loginGuard: any

    beforeEach(() => {
        loginGuard = {
            tokenDecode: vi.fn().mockName("LoginGuard.tokenDecode"),
            forbidRoute: vi.fn().mockName("LoginGuard.forbidRoute")
        }

        TestBed.configureTestingModule({
            imports: [RouterTestingModule.withRoutes([
                    { path: '403', component: ErrorPageComponent }
                ])],
            providers: [
                AdminGuard,
                { provide: LoginGuard, useValue: loginGuard },
                provideHttpClient(withInterceptorsFromDi()),
                provideHttpClientTesting()
            ]
        })
    })

    it('should be created', () => {
        const guard = TestBed.inject(AdminGuard)

        expect(guard).toBeTruthy()
    })

    it('should open for admins', () => {
        const guard = TestBed.inject(AdminGuard)

        loginGuard.tokenDecode.mockReturnValue({ data: { role: 'admin' } })
        expect(guard.canActivate()).toBe(true)
    })

    it('should close for regular customers', () => {
        const guard = TestBed.inject(AdminGuard)

        loginGuard.tokenDecode.mockReturnValue({ data: { role: 'customer' } })
        expect(guard.canActivate()).toBe(false)
        expect(loginGuard.forbidRoute).toHaveBeenCalled()
    })

    it('should close for deluxe customers', () => {
        const guard = TestBed.inject(AdminGuard)

        loginGuard.tokenDecode.mockReturnValue({ data: { role: 'deluxe' } })
        expect(guard.canActivate()).toBe(false)
        expect(loginGuard.forbidRoute).toHaveBeenCalled()
    })

    it('should close for accountants', () => {
        const guard = TestBed.inject(AdminGuard)

        loginGuard.tokenDecode.mockReturnValue({ data: { role: 'accounting' } })
        expect(guard.canActivate()).toBe(false)
        expect(loginGuard.forbidRoute).toHaveBeenCalled()
    })
})

describe('AccountingGuard', () => {
    let loginGuard: any

    beforeEach(() => {
        loginGuard = {
            tokenDecode: vi.fn().mockName("LoginGuard.tokenDecode"),
            forbidRoute: vi.fn().mockName("LoginGuard.forbidRoute")
        }

        TestBed.configureTestingModule({
            imports: [RouterTestingModule.withRoutes([
                    { path: '403', component: ErrorPageComponent }
                ])],
            providers: [
                AccountingGuard,
                { provide: LoginGuard, useValue: loginGuard },
                provideHttpClient(withInterceptorsFromDi()),
                provideHttpClientTesting()
            ]
        })
    })

    it('should be created', () => {
        const guard = TestBed.inject(AccountingGuard)

        expect(guard).toBeTruthy()
    })

    it('should open for accountants', () => {
        const guard = TestBed.inject(AccountingGuard)

        loginGuard.tokenDecode.mockReturnValue({ data: { role: 'accounting' } })
        expect(guard.canActivate()).toBe(true)
    })

    it('should close for regular customers', () => {
        const guard = TestBed.inject(AccountingGuard)

        loginGuard.tokenDecode.mockReturnValue({ data: { role: 'customer' } })
        expect(guard.canActivate()).toBe(false)
        expect(loginGuard.forbidRoute).toHaveBeenCalled()
    })

    it('should close for deluxe customers', () => {
        const guard = TestBed.inject(AccountingGuard)

        loginGuard.tokenDecode.mockReturnValue({ data: { role: 'deluxe' } })
        expect(guard.canActivate()).toBe(false)
        expect(loginGuard.forbidRoute).toHaveBeenCalled()
    })

    it('should close for admins', () => {
        const guard = TestBed.inject(AccountingGuard)

        loginGuard.tokenDecode.mockReturnValue({ data: { role: 'admin' } })
        expect(guard.canActivate()).toBe(false)
        expect(loginGuard.forbidRoute).toHaveBeenCalled()
    })
})

describe('DeluxeGuard', () => {
    let loginGuard: any

    beforeEach(() => {
        loginGuard = {
            tokenDecode: vi.fn().mockName("LoginGuard.tokenDecode")
        }

        TestBed.configureTestingModule({
            imports: [RouterTestingModule.withRoutes([
                    { path: '403', component: ErrorPageComponent }
                ])],
            providers: [
                DeluxeGuard,
                { provide: LoginGuard, useValue: loginGuard },
                provideHttpClient(withInterceptorsFromDi()),
                provideHttpClientTesting()
            ]
        })
    })

    it('should be created', () => {
        const guard = TestBed.inject(DeluxeGuard)

        expect(guard).toBeTruthy()
    })

    it('should open for deluxe customers', () => {
        const guard = TestBed.inject(DeluxeGuard)

        loginGuard.tokenDecode.mockReturnValue({ data: { role: 'deluxe' } })
        expect(guard.isDeluxe()).toBe(true)
    })

    it('should close for regular customers', () => {
        const guard = TestBed.inject(DeluxeGuard)

        loginGuard.tokenDecode.mockReturnValue({ data: { role: 'customer' } })
        expect(guard.isDeluxe()).toBe(false)
    })

    it('should close for admins', () => {
        const guard = TestBed.inject(DeluxeGuard)

        loginGuard.tokenDecode.mockReturnValue({ data: { role: 'admin' } })
        expect(guard.isDeluxe()).toBe(false)
    })

    it('should close for accountants', () => {
        const guard = TestBed.inject(DeluxeGuard)

        loginGuard.tokenDecode.mockReturnValue({ data: { role: 'accounting' } })
        expect(guard.isDeluxe()).toBe(false)
    })
})
