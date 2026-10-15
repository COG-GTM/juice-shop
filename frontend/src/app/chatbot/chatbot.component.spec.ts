/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type ComponentFixture, TestBed } from '@angular/core/testing'
import { RouterModule } from '@angular/router'
import { ChatbotComponent } from './chatbot.component'
import { LoginGuard } from '../app.guard'

describe('ChatbotComponent', () => {
    let component: ChatbotComponent
    let fixture: ComponentFixture<ChatbotComponent>
    let loginGuard: any

    beforeEach(() => {
        loginGuard = {
            canActivate: vi.fn().mockName('LoginGuard.canActivate').mockReturnValue(true)
        }

        TestBed.configureTestingModule({
            imports: [
                RouterModule.forRoot([], { useHash: true }),
                ChatbotComponent
            ],
            providers: [
                { provide: LoginGuard, useValue: loginGuard }
            ]
        }).compileComponents()

    })

    function createComponent () {
        fixture = TestBed.createComponent(ChatbotComponent)
        component = fixture.componentInstance
        fixture.detectChanges()
    }

    it('should create', () => {
        createComponent()
        expect(component).toBeTruthy()
    })

    it('should require a logged-in user', () => {
        createComponent()
        expect(loginGuard.canActivate).toHaveBeenCalled()
    })

    it('should render the chatbot container', () => {
        createComponent()
        const container = fixture.nativeElement.querySelector('.chatbot-container')
        expect(container).toBeTruthy()
    })

    it('should contain a router-outlet', () => {
        createComponent()
        const outlet = fixture.nativeElement.querySelector('router-outlet')
        expect(outlet).toBeTruthy()
    })

    it('should not render the router-outlet for logged-out users', () => {
        loginGuard.canActivate.mockReturnValue(false)
        createComponent()
        const outlet = fixture.nativeElement.querySelector('router-outlet')
        expect(outlet).toBeFalsy()
    })
})
