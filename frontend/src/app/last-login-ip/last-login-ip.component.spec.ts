/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { TranslateModule, TranslateService } from '@ngx-translate/core'
import { EventEmitter } from '@angular/core'
import { of, throwError } from 'rxjs'
import { type ComponentFixture, TestBed } from '@angular/core/testing'
import { LastLoginIpComponent } from './last-login-ip.component'
import { MatCardModule } from '@angular/material/card'
import { DomSanitizer } from '@angular/platform-browser'
import { UserService } from '../Services/user.service'

describe('LastLoginIpComponent', () => {
    let component: LastLoginIpComponent
    let fixture: ComponentFixture<LastLoginIpComponent>
    let sanitizer
    let translateService
    let userService

    beforeEach(async () => {
        sanitizer = {
            bypassSecurityTrustHtml: vi.fn().mockName("DomSanitizer.bypassSecurityTrustHtml"),
            sanitize: vi.fn().mockName("DomSanitizer.sanitize")
        }
        sanitizer.bypassSecurityTrustHtml.mockImplementation((args: any) => args)
        sanitizer.sanitize.mockReturnValue({})
        userService = {
            whoAmI: vi.fn().mockName("UserService.whoAmI")
        }
        userService.whoAmI.mockReturnValue(of({}))
        translateService = {
            get: vi.fn().mockName("TranslateService.get")
        }
        translateService.get.mockReturnValue(of({}))
        translateService.onLangChange = new EventEmitter()
        translateService.onTranslationChange = new EventEmitter()
        translateService.onFallbackLangChange = new EventEmitter()
        translateService.onDefaultLangChange = new EventEmitter()

        TestBed.configureTestingModule({
            providers: [
                { provide: DomSanitizer, useValue: sanitizer },
                { provide: UserService, useValue: userService },
                { provide: TranslateService, useValue: translateService }
            ],
            imports: [
                MatCardModule,
                LastLoginIpComponent,
                TranslateModule.forRoot()
            ]
        }).compileComponents()
    })

    beforeEach(() => {
        localStorage.clear()
        fixture = TestBed.createComponent(LastLoginIpComponent)
        component = fixture.componentInstance
        fixture.detectChanges()
    })

    afterEach(() => {
        localStorage.clear()
    })

    it('should compile', () => {
        expect(component).toBeTruthy()
    })

    it('should log whoami error to console', () => {
        console.log = vi.fn()
        userService.whoAmI.mockReturnValue(throwError(() => new Error('Error')))
        component.ngOnInit()
        expect(console.log).toHaveBeenCalled()
    })

    it('should set Last-Login IP from whoami as trusted HTML', () => {
        userService.whoAmI.mockReturnValue(of({ lastLoginIp: '1.2.3.4' }))
        component.ngOnInit()
        expect(sanitizer.bypassSecurityTrustHtml).toHaveBeenCalledWith('<small>1.2.3.4</small>')
    })

    it('should not set Last-Login IP if whoami returns none', () => {
        userService.whoAmI.mockReturnValue(of({ id: 1 }))
        component.ngOnInit()
        expect(sanitizer.bypassSecurityTrustHtml).not.toHaveBeenCalled()
    })
})
