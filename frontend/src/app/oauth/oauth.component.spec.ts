/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type ComponentFixture, TestBed } from '@angular/core/testing'
import { TranslateModule } from '@ngx-translate/core'
import { MatIconModule } from '@angular/material/icon'
import { MatCheckboxModule } from '@angular/material/checkbox'
import { MatFormFieldModule } from '@angular/material/form-field'
import { MatCardModule } from '@angular/material/card'
import { MatInputModule } from '@angular/material/input'

import { provideHttpClientTesting } from '@angular/common/http/testing'
import { RouterTestingModule } from '@angular/router/testing'

import { OAuthComponent } from './oauth.component'
import { LoginComponent } from '../login/login.component'
import { ReactiveFormsModule } from '@angular/forms'
import { ActivatedRoute } from '@angular/router'
import { MatTooltipModule } from '@angular/material/tooltip'
import { of, throwError } from 'rxjs'
import { UserService } from '../Services/user.service'
import { CookieModule } from 'ngy-cookie'
import { provideHttpClient, withInterceptorsFromDi } from '@angular/common/http'

describe('OAuthComponent', () => {
    let component: OAuthComponent
    let fixture: ComponentFixture<OAuthComponent>
    let userService: any

    beforeEach(async () => {
        userService = {
            oauthLogin: vi.fn().mockName("UserService.oauthLogin"),
            login: vi.fn().mockName("UserService.login"),
            save: vi.fn().mockName("UserService.save")
        }
        userService.oauthLogin.mockReturnValue(of({ token: 'TOKEN', bid: 1 }))
        userService.login.mockReturnValue(of({}))
        userService.save.mockReturnValue(of({}))
        userService.isLoggedIn = {
            next: vi.fn().mockName("userService.isLoggedIn.next")
        }
        userService.isLoggedIn.next.mockReturnValue({})

        TestBed.configureTestingModule({
            imports: [RouterTestingModule.withRoutes([
                    { path: 'login', component: LoginComponent }
                ]),
                ReactiveFormsModule,
                CookieModule.forRoot(),
                TranslateModule.forRoot(),
                MatInputModule,
                MatIconModule,
                MatCardModule,
                MatFormFieldModule,
                MatCheckboxModule,
                MatTooltipModule,
                OAuthComponent, LoginComponent],
            providers: [
                { provide: ActivatedRoute, useValue: { snapshot: { data: { params: '?alt=json&access_token=TEST&state=STATE' } } } },
                { provide: UserService, useValue: userService },
                provideHttpClient(withInterceptorsFromDi()),
                provideHttpClientTesting()
            ]
        })
            .compileComponents()
    })

    beforeEach(() => {
        sessionStorage.setItem('oauthState', 'STATE')
        fixture = TestBed.createComponent(OAuthComponent)
        component = fixture.componentInstance
        fixture.detectChanges()
    })

    it('should create', () => {
        expect(component).toBeTruthy()
    })

    it('removes authentication token and basket id on failed OAuth login attempt', () => {
        vi.spyOn(console, 'log').mockImplementation(() => {})
        userService.oauthLogin.mockReturnValue(throwError({ error: 'Error' }))
        sessionStorage.setItem('oauthState', 'STATE')
        component.ngOnInit()
        expect(localStorage.getItem('token')).toBeNull()
        expect(sessionStorage.getItem('bid')).toBeNull()
    })

    it('continues with the two-factor screen when the server requires a TOTP token', () => {
        userService.oauthLogin.mockReturnValue(throwError({ error: { status: 'totp_token_required', data: { tmpToken: 'TMP' } } }))
        sessionStorage.setItem('oauthState', 'STATE')
        component.ngOnInit()
        expect(localStorage.getItem('totp_tmp_token')).toBe('TMP')
        localStorage.removeItem('totp_tmp_token')
    })

    it('passes the OAuth access token to the server-side login', () => {
        sessionStorage.setItem('oauthState', 'STATE')
        component.ngOnInit()
        expect(userService.oauthLogin).toHaveBeenCalledWith('TEST')
    })

    it('stores the session issued by the server after successful OAuth login', () => {
        sessionStorage.setItem('oauthState', 'STATE')
        localStorage.removeItem('token')
        sessionStorage.removeItem('bid')
        userService.oauthLogin.mockReturnValue(of({ token: 'SERVER_TOKEN', bid: 42 }))
        component.ngOnInit()
        expect(localStorage.getItem('token')).toBe('SERVER_TOKEN')
        expect(sessionStorage.getItem('bid')).toBe('42')
        expect(userService.isLoggedIn.next).toHaveBeenCalledWith(true)
    })

    it('rejects the redirect without calling the server when the state does not match', () => {
        vi.spyOn(console, 'log').mockImplementation(() => {})
        userService.oauthLogin.mockClear()
        sessionStorage.setItem('oauthState', 'OTHER')
        component.ngOnInit()
        expect(userService.oauthLogin).not.toHaveBeenCalled()
        expect(sessionStorage.getItem('oauthState')).toBeNull()
    })

    it('rejects the redirect when no state was stored before leaving for Google', () => {
        vi.spyOn(console, 'log').mockImplementation(() => {})
        userService.oauthLogin.mockClear()
        sessionStorage.removeItem('oauthState')
        component.ngOnInit()
        expect(userService.oauthLogin).not.toHaveBeenCalled()
    })

    it('never registers or logs in with a password derived from the email', () => {
        userService.oauthLogin.mockReturnValue(of({ token: 'SERVER_TOKEN', bid: 42 }))
        component.ngOnInit()
        expect(userService.save).not.toHaveBeenCalled()
        expect(userService.login).not.toHaveBeenCalled()
    })
})
