/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type ComponentFixture, TestBed } from '@angular/core/testing'

import { PasswordStrengthComponent } from './password-strength.component'
import { provideZoneChangeDetection, SimpleChange } from '@angular/core'

describe('PasswordStrengthComponent', () => {
    let component: PasswordStrengthComponent
    let fixture: ComponentFixture<PasswordStrengthComponent>

    let firstPasswordChange = true

    const setPassword = (password: string) => {
        const previous = component.password
        component.password = password
        component.ngOnChanges({ password: new SimpleChange(previous, password, firstPasswordChange) })
        firstPasswordChange = false
        fixture.detectChanges()
    }

    beforeEach(async () => {
        await TestBed.configureTestingModule({
            imports: [PasswordStrengthComponent],
            providers: [provideZoneChangeDetection()]
        }).compileComponents()

        fixture = TestBed.createComponent(PasswordStrengthComponent)
        component = fixture.componentInstance
        firstPasswordChange = true
        fixture.detectChanges()
    })

    it('should create', () => {
        expect(component).toBeTruthy()
    })

    it('should render mat-progress-bar', () => {
        const progressBar = fixture.nativeElement.querySelector('mat-progress-bar')
        expect(progressBar).toBeTruthy()
    })

    it('should bind progress input to mat-progress-bar value', () => {
        component.passwordStrength = 50
        fixture.detectChanges()

        const progressBarDebug = fixture.debugElement.nativeElement.querySelector('mat-progress-bar')
        expect(progressBarDebug).toBeTruthy()

        const matProgressBarInstance = fixture.debugElement.children.find((el) => el.nativeElement.tagName.toLowerCase() === 'mat-progress-bar')?.componentInstance

        expect(matProgressBarInstance.value).toBe(50)
    })

    it('should apply correct class based on progress value', () => {
        const progressBar = fixture.nativeElement.querySelector('mat-progress-bar')

        component.passwordStrength = 0
        fixture.detectChanges()
        expect(progressBar.classList).toContain('low')

        component.passwordStrength = 20
        fixture.detectChanges()
        expect(progressBar.classList).toContain('low')

        component.passwordStrength = 40
        fixture.detectChanges()
        expect(progressBar.classList).toContain('low-medium')

        component.passwordStrength = 60
        fixture.detectChanges()
        expect(progressBar.classList).toContain('medium')

        component.passwordStrength = 80
        fixture.detectChanges()
        expect(progressBar.classList).toContain('high-medium')

        component.passwordStrength = 100
        fixture.detectChanges()
        expect(progressBar.classList).toContain('high')
    })

    it('should have correct ARIA attributes for accessibility', () => {
        const progressBar = fixture.nativeElement.querySelector('mat-progress-bar')
        expect(progressBar.getAttribute('role')).toBe('progressbar')
        expect(progressBar.getAttribute('aria-valuemin')).toBe('0')
        expect(progressBar.getAttribute('aria-valuemax')).toBe('100')
    })

    it('should update aria-valuenow based on progress value', () => {
        component.passwordStrength = 45
        fixture.detectChanges()
        const progressBar = fixture.nativeElement.querySelector('mat-progress-bar')
        expect(progressBar.getAttribute('aria-valuenow')).toBe('45')
    })

    it('should not recalculate strength when password did not change', () => {
        component.password = 'Str0ng!Password'
        component.ngOnChanges({})
        expect(component.passwordStrength).toBe(0)
    })

    it('should score an empty password as 0', () => {
        setPassword('')
        expect(component.passwordStrength).toBe(0)
    })

    it('should score each additional fulfilled check with 20 percent', () => {
        setPassword('abcdefgh')
        expect(component.passwordStrength).toBe(40)

        setPassword('Abcdefgh')
        expect(component.passwordStrength).toBe(60)

        setPassword('Abcdefg1')
        expect(component.passwordStrength).toBe(80)

        setPassword('Abcdefg1!')
        expect(component.passwordStrength).toBe(100)
    })

    it('should score a short lowercase-only password with a single check', () => {
        setPassword('abc')
        expect(component.passwordStrength).toBe(20)
    })

    it('should reflect the calculated strength in the progress bar', () => {
        setPassword('Abcdefg1!')
        const progressBar = fixture.nativeElement.querySelector('mat-progress-bar')
        expect(progressBar.getAttribute('aria-valuenow')).toBe('100')
        expect(progressBar.classList).toContain('high')
    })

    it('should require at least the minimum number of characters', () => {
        setPassword('Abcdef1')
        expect(component.containAtLeastMinChars).toBe(false)

        setPassword('Abcdefg1')
        expect(component.containAtLeastMinChars).toBe(true)
    })

    it('should detect lower case letters', () => {
        setPassword('ABCDEFG1!')
        expect(component.containAtLeastOneLowerCaseLetter).toBe(false)

        setPassword('ABCDEFg1!')
        expect(component.containAtLeastOneLowerCaseLetter).toBe(true)
    })

    it('should detect upper case letters', () => {
        setPassword('abcdefg1!')
        expect(component.containAtLeastOneUpperCaseLetter).toBe(false)

        setPassword('abcdefG1!')
        expect(component.containAtLeastOneUpperCaseLetter).toBe(true)
    })

    it('should detect digits', () => {
        setPassword('Abcdefgh!')
        expect(component.containAtLeastOneDigit).toBe(false)

        setPassword('Abcdefg1!')
        expect(component.containAtLeastOneDigit).toBe(true)
    })

    it('should detect special characters', () => {
        setPassword('Abcdefg1')
        expect(component.containAtLeastOneSpecialChar).toBe(false)

        setPassword('Abcdefg1#')
        expect(component.containAtLeastOneSpecialChar).toBe(true)

        setPassword('Abcdefg1 ')
        expect(component.containAtLeastOneSpecialChar).toBe(true)
    })
})
