/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { TranslateModule } from '@ngx-translate/core'
import { provideHttpClientTesting } from '@angular/common/http/testing'
import { MatCardModule } from '@angular/material/card'
import { MatFormFieldModule } from '@angular/material/form-field'
import { type ComponentFixture, TestBed } from '@angular/core/testing'
import { MatInputModule } from '@angular/material/input'
import { ReactiveFormsModule } from '@angular/forms'

import { of } from 'rxjs'
import { RouterTestingModule } from '@angular/router/testing'
import { DeluxeUserComponent } from './deluxe-user.component'
import { UserService } from '../Services/user.service'
import { CookieService } from 'ngy-cookie'
import { LoginComponent } from '../login/login.component'
import { Location } from '@angular/common'
import { MatTableModule } from '@angular/material/table'
import { MatExpansionModule } from '@angular/material/expansion'
import { MatDividerModule } from '@angular/material/divider'
import { MatRadioModule } from '@angular/material/radio'
import { MatDialogModule } from '@angular/material/dialog'
import { MatIconModule } from '@angular/material/icon'
import { MatCheckboxModule } from '@angular/material/checkbox'
import { MatTooltipModule } from '@angular/material/tooltip'
import { ConfigurationService } from '../Services/configuration.service'
import { throwError } from 'rxjs/internal/observable/throwError'
import { provideHttpClient, withInterceptorsFromDi } from '@angular/common/http'
import { ActivatedRoute } from '@angular/router'
import { SocketIoService } from '../Services/socket-io.service'

describe('DeluxeUserComponent', () => {
    let component: DeluxeUserComponent
    let fixture: ComponentFixture<DeluxeUserComponent>
    let userService
    let cookieService: any
    let configurationService: any
    let socketIoService: any
    let mockSocket: any

    beforeEach(async () => {
        configurationService = {
            getApplicationConfiguration: vi.fn().mockName("ConfigurationService.getApplicationConfiguration")
        }
        configurationService.getApplicationConfiguration.mockReturnValue(of({ application: {} }))
        userService = {
            deluxeStatus: vi.fn().mockName("UserService.deluxeStatus"),
            upgradeToDeluxe: vi.fn().mockName("UserService.upgradeToDeluxe"),
            saveLastLoginIp: vi.fn().mockName("UserService.saveLastLoginIp")
        }
        userService.deluxeStatus.mockReturnValue(of({}))
        userService.upgradeToDeluxe.mockReturnValue(of({}))
        userService.isLoggedIn = {
            next: vi.fn().mockName("userService.isLoggedIn.next")
        }
        userService.isLoggedIn.next.mockReturnValue({})
        userService.saveLastLoginIp.mockReturnValue(of({}))
        mockSocket = { emit: vi.fn() }
        socketIoService = {
            socket: vi.fn().mockReturnValue(mockSocket)
        }
        cookieService = {
            remove: vi.fn().mockName("CookieService.remove")
        }

        TestBed.configureTestingModule({
            imports: [RouterTestingModule.withRoutes([
                    { path: 'login', component: LoginComponent }
                ]),
                TranslateModule.forRoot(),
                ReactiveFormsModule,
                MatCardModule,
                MatTableModule,
                MatFormFieldModule,
                MatInputModule,
                MatExpansionModule,
                MatDividerModule,
                MatRadioModule,
                MatDialogModule,
                MatIconModule,
                MatCheckboxModule,
                MatTooltipModule,
                DeluxeUserComponent, LoginComponent],
            providers: [
                { provide: UserService, useValue: userService },
                { provide: ConfigurationService, useValue: configurationService },
                { provide: CookieService, useValue: cookieService },
                { provide: SocketIoService, useValue: socketIoService },
                provideHttpClient(withInterceptorsFromDi()),
                provideHttpClientTesting()
            ]
        })
            .compileComponents()
        TestBed.inject(Location)
    })

    beforeEach(() => {
        fixture = TestBed.createComponent(DeluxeUserComponent)
        component = fixture.componentInstance
        fixture.detectChanges()
    })

    it('should create', () => {
        expect(component).toBeTruthy()
    })

    it('should hold membership cost on ngOnInit', () => {
        userService.deluxeStatus.mockReturnValue(of({ membershipCost: 30 }))
        component.ngOnInit()
        expect(component.membershipCost).toEqual(30)
    })

    it('should set application name and logo as obtained from configuration', () => {
        configurationService.getApplicationConfiguration.mockReturnValue(of({ application: { name: 'Name', logo: 'Logo' } }))
        component.ngOnInit()

        expect(component.applicationName).toBe('Name')
        expect(component.logoSrc).toBe('assets/public/images/Logo')
    })

    it('should assemble internal logo location from image base path and URL obtained from configuration', () => {
        configurationService.getApplicationConfiguration.mockReturnValue(of({ application: { logo: 'http://test.com/logo.jpg' } }))
        component.ngOnInit()

        expect(component.logoSrc).toBe('assets/public/images/logo.jpg')
    })

    it('should log error on failure in retrieving configuration from backend', () => {
        configurationService.getApplicationConfiguration.mockReturnValue(throwError('Error'))
        console.log = vi.fn()
        component.ngOnInit()
        expect(console.log).toHaveBeenCalledWith('Error')
    })

    describe('testDecal query parameter', () => {
        const setTestDecal = (testDecal: unknown) => {
            TestBed.inject(ActivatedRoute).snapshot.queryParams = { testDecal }
            configurationService.getApplicationConfiguration.mockReturnValue(of({ application: { logo: 'JuiceShop_Logo.png' } }))
            component.ngOnInit()
        }

        it('should use a plain image file name as decal', () => {
            setTestDecal('JuiceShop_Logo.svg')
            expect(component.logoSrc).toBe('assets/public/images/JuiceShop_Logo.svg')
        })

        it('should ignore a decal traversing to the redirect endpoint and keep the configured logo', () => {
            setTestDecal('../../../redirect?to=https://placecats.com/g/200/100?x=https://github.com/juice-shop/juice-shop')
            expect(component.logoSrc).toBe('assets/public/images/JuiceShop_Logo.png')
        })

        it('should ignore decals containing path separators or parent directory segments', () => {
            for (const decal of ['../JuiceShop_Logo.png', 'deluxe/../../x.png', '..\\x.png', '/redirect.png', '//evil.example/x.png', 'products/apple_juice.jpg', '..']) {
                setTestDecal(decal)
                expect(component.logoSrc).toBe('assets/public/images/JuiceShop_Logo.png')
            }
        })

        it('should ignore decals with absolute URLs or non-image file names', () => {
            for (const decal of ['https://evil.example/x.png', 'javascript:alert(1)', 'x.png?to=https://evil.example', 'x.html']) {
                setTestDecal(decal)
                expect(component.logoSrc).toBe('assets/public/images/JuiceShop_Logo.png')
            }
        })

        it('should ignore a decal passed more than once', () => {
            setTestDecal(['JuiceShop_Logo.svg', '../../../redirect?to=https://evil.example'])
            expect(component.logoSrc).toBe('assets/public/images/JuiceShop_Logo.png')
        })
    })
})
