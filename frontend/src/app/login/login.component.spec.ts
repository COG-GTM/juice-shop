/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { SearchResultComponent } from '../search-result/search-result.component'
import { WindowRefService } from '../Services/window-ref.service'
import { BasketService } from '../Services/basket.service'
import { provideHttpClientTesting } from '@angular/common/http/testing'
import { UserService } from '../Services/user.service'
import { type ComponentFixture, TestBed } from '@angular/core/testing'
import { LoginComponent } from './login.component'
import { ActivatedRoute, Router } from '@angular/router'
import { RouterTestingModule } from '@angular/router/testing'
import { ReactiveFormsModule } from '@angular/forms'

import { MatIconModule } from '@angular/material/icon'
import { MatCheckboxModule } from '@angular/material/checkbox'
import { MatFormFieldModule } from '@angular/material/form-field'
import { MatCardModule } from '@angular/material/card'
import { MatInputModule } from '@angular/material/input'
import { CookieModule, CookieService } from 'ngy-cookie'
import { Location } from '@angular/common'
import { of, throwError } from 'rxjs'
import { MatTableModule } from '@angular/material/table'
import { MatPaginatorModule } from '@angular/material/paginator'
import { MatDialogModule } from '@angular/material/dialog'
import { MatDividerModule } from '@angular/material/divider'
import { TranslateModule } from '@ngx-translate/core'
import { MatGridListModule } from '@angular/material/grid-list'
import { MatTooltipModule } from '@angular/material/tooltip'
import { provideHttpClient, withInterceptorsFromDi } from '@angular/common/http'

describe('LoginComponent', () => {
    let component: LoginComponent
    let fixture: ComponentFixture<LoginComponent>
    let userService: any
    let basketService: BasketService
    let router: Router
    let route: ActivatedRoute
    let location: Location

    beforeEach(async () => {
        userService = {
            login: vi.fn().mockName("UserService.login")
        }
        userService.login.mockReturnValue(of({}))
        userService.isLoggedIn = {
            next: vi.fn().mockName("userService.isLoggedIn.next")
        }
        userService.isLoggedIn.next.mockReturnValue({})

        TestBed.configureTestingModule({
            imports: [RouterTestingModule.withRoutes([
                    { path: 'search', component: SearchResultComponent }
                ]),
                ReactiveFormsModule,
                CookieModule.forRoot(),
                TranslateModule.forRoot(),
                MatCheckboxModule,
                MatFormFieldModule,
                MatCardModule,
                MatIconModule,
                MatInputModule,
                MatTableModule,
                MatPaginatorModule,
                MatDialogModule,
                MatDividerModule,
                MatGridListModule,
                MatTooltipModule,
                LoginComponent, SearchResultComponent],
            providers: [
                { provide: UserService, useValue: userService },
                WindowRefService,
                CookieService,
                provideHttpClient(withInterceptorsFromDi()),
                provideHttpClientTesting()
            ]
        })
            .compileComponents()

        location = TestBed.inject(Location)
        basketService = TestBed.inject(BasketService)
        router = TestBed.inject(Router)
        route = TestBed.inject(ActivatedRoute)
    })

    beforeEach(() => {
        localStorage.removeItem('token')
        localStorage.removeItem('email')
        localStorage.removeItem('totp_tmp_token')
        sessionStorage.removeItem('bid')
        fixture = TestBed.createComponent(LoginComponent)
        component = fixture.componentInstance
        fixture.detectChanges()
    })

    afterEach(() => {
        vi.restoreAllMocks()
    })

    it('should create', () => {
        expect(component).toBeTruthy()
    })

    it('should have email as compulsory', () => {
        component.emailControl.setValue('')
        expect(component.emailControl.valid).toBeFalsy()
        component.emailControl.setValue('Value')
        expect(component.emailControl.valid).toBe(true)
    })

    it('should have password as compulsory', () => {
        component.passwordControl.setValue('')
        expect(component.passwordControl.valid).toBeFalsy()
        component.passwordControl.setValue('Value')
        expect(component.passwordControl.valid).toBe(true)
    })

    it('should have remember-me checked if email token is present as in localStorage', () => {
        localStorage.setItem('email', 'a@a')
        component.ngOnInit()
        expect(component.rememberMe.value).toBe(true)
    })

    it('should have remember-me unchecked if email token is not present in localStorage', () => {
        component.ngOnInit()
        expect(component.rememberMe.value).toBeFalsy()
    })

    it('should flag OAuth as disabled if server is running on unauthorized redirect URI', () => {
        expect(component.oauthUnavailable).toBe(true)
    })

    it('forwards to main page after successful login', async () => {
        userService.login.mockReturnValue(of({}))
        component.login()
        await fixture.whenStable()
        expect(location.path()).toBe('/search')
    })

    it('stores the returned authentication token in localStorage', () => {
        userService.login.mockReturnValue(of({ token: 'token' }))
        component.login()
        expect(localStorage.getItem('token')).toBe('token')
    })

    it('puts the returned basket id into browser session storage', () => {
        userService.login.mockReturnValue(of({ bid: 4711 }))
        component.login()
        expect(sessionStorage.getItem('bid')).toBe('4711')
    })

    it('removes authentication token and basket id on failed login attempt', () => {
        userService.login.mockReturnValue(throwError({ error: 'Error' }))
        component.login()
        expect(localStorage.getItem('token')).toBeNull()
        expect(sessionStorage.getItem('bid')).toBeNull()
    })

    it('returns error message from server to client on failed login attempt', () => {
        userService.login.mockReturnValue(throwError({ error: 'Error' }))
        component.login()
        expect(component.error).toBeTruthy()
    })

    it('sets form to pristine on failed login attempt', () => {
        userService.login.mockReturnValue(throwError({ error: 'Error' }))
        component.login()
        expect(component.emailControl.pristine).toBe(true)
        expect(component.passwordControl.pristine).toBe(true)
    })

    it('puts current email into "email" cookie on successful login with remember-me checkbox ticked', () => {
        userService.login.mockReturnValue(of({}))
        component.emailControl.setValue('horst@juice-sh.op')
        component.rememberMe.setValue(true)
        component.login()
        expect(localStorage.getItem('email')).toBe('horst@juice-sh.op')
    })

    it('puts current email into "email" cookie on failed login with remember-me checkbox ticked', () => {
        userService.login.mockReturnValue(throwError({ error: 'Error' }))
        component.emailControl.setValue('horst@juice-sh.op')
        component.rememberMe.setValue(true)
        component.login()
        expect(localStorage.getItem('email')).toBe('horst@juice-sh.op')
    })

    it('merges the guest basket into the user basket on successful login', () => {
        const mergeGuestBasket = vi.spyOn(basketService, 'mergeGuestBasketIntoUserBasket').mockReturnValue(of(void 0))
        userService.login.mockReturnValue(of({ token: 'token', bid: 4711 }))
        component.login()
        expect(mergeGuestBasket).toHaveBeenCalledWith(4711)
    })

    it('completes login even if merging the guest basket fails', async () => {
        vi.spyOn(basketService, 'mergeGuestBasketIntoUserBasket').mockReturnValue(throwError(() => new Error('Merge failed')))
        userService.login.mockReturnValue(of({ token: 'token', bid: 4711 }))
        component.login()
        await fixture.whenStable()
        expect(userService.isLoggedIn.next).toHaveBeenCalledWith(true)
        expect(location.path()).toBe('/search')
    })

    it('forwards to the redirect URL given as query parameter after successful login', () => {
        vi.spyOn(route.snapshot.queryParamMap, 'get').mockReturnValue('/basket')
        const navigateByUrl = vi.spyOn(router, 'navigateByUrl').mockResolvedValue(true)
        userService.login.mockReturnValue(of({ token: 'token' }))
        component.login()
        expect(navigateByUrl).toHaveBeenCalledWith('/basket')
    })

    it('stores the temporary token and forwards to 2FA entry when a TOTP token is required', () => {
        const navigate = vi.spyOn(router, 'navigate').mockResolvedValue(true)
        userService.login.mockReturnValue(throwError({ error: { status: 'totp_token_required', data: { tmpToken: 'tmpToken' } } }))
        component.login()
        expect(localStorage.getItem('totp_tmp_token')).toBe('tmpToken')
        expect(navigate).toHaveBeenCalledWith(['/2fa/enter'])
    })

    it('keeps the authentication token and error untouched when a TOTP token is required', () => {
        vi.spyOn(router, 'navigate').mockResolvedValue(true)
        localStorage.setItem('token', 'token')
        userService.login.mockReturnValue(throwError({ error: { status: 'totp_token_required', data: { tmpToken: 'tmpToken' } } }))
        component.login()
        expect(localStorage.getItem('token')).toBe('token')
        expect(component.error).toBeUndefined()
        expect(userService.isLoggedIn.next).not.toHaveBeenCalled()
    })

    it('redirects to the OAuth provider on Google login', () => {
        const replace = vi.fn()
        vi.spyOn(WindowRefService.prototype, 'nativeWindow', 'get').mockReturnValue({ location: { replace } })
        component.clientId = 'clientId'
        component.redirectUri = 'http://localhost:3000'
        component.googleLogin()
        expect(replace).toHaveBeenCalledWith('https://accounts.google.com/o/oauth2/v2/auth?client_id=clientId&response_type=token&scope=email&redirect_uri=http://localhost:3000')
    })
})
