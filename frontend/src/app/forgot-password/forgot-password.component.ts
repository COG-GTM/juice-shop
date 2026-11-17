/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { UserService } from '../Services/user.service'
import { type AbstractControl, UntypedFormControl, Validators, FormsModule, ReactiveFormsModule } from '@angular/forms'
import { Component, inject } from '@angular/core'
import { ActivatedRoute } from '@angular/router'
import { library } from '@fortawesome/fontawesome-svg-core'
import { faSave } from '@fortawesome/free-solid-svg-icons'
import { faEdit } from '@fortawesome/free-regular-svg-icons'
import { TranslateService, TranslateModule } from '@ngx-translate/core'
import { MatButtonModule } from '@angular/material/button'
import { PasswordStrengthComponent } from '../password-strength/password-strength.component'
import { PasswordStrengthInfoComponent } from '../password-strength-info/password-strength-info.component'
import { MatSlideToggle } from '@angular/material/slide-toggle'

import { MatTooltip } from '@angular/material/tooltip'
import { MatIconModule } from '@angular/material/icon'
import { MatInputModule } from '@angular/material/input'
import { MatFormFieldModule, MatLabel, MatSuffix, MatError, MatHint } from '@angular/material/form-field'
import { MatCardModule } from '@angular/material/card'

library.add(faSave, faEdit)

@Component({
  selector: 'app-forgot-password',
  templateUrl: './forgot-password.component.html',
  styleUrls: ['./forgot-password.component.scss'],
  imports: [MatCardModule, TranslateModule, MatFormFieldModule, MatLabel, MatInputModule, FormsModule, ReactiveFormsModule, MatIconModule, MatSuffix, MatTooltip, MatError, MatHint, MatSlideToggle, PasswordStrengthComponent, PasswordStrengthInfoComponent, MatButtonModule]
})
export class ForgotPasswordComponent {
  private readonly userService = inject(UserService)
  private readonly translate = inject(TranslateService)
  private readonly route = inject(ActivatedRoute)

  public resetToken: string | null = this.route.snapshot.queryParamMap.get('token')
  public emailControl: UntypedFormControl = new UntypedFormControl('', [Validators.required, Validators.email])
  public passwordControl: UntypedFormControl = new UntypedFormControl('', [Validators.required, Validators.minLength(5)])
  public repeatPasswordControl: UntypedFormControl = new UntypedFormControl('', [Validators.required, matchValidator(this.passwordControl)])
  public error?: string
  public confirmation?: string

  requestResetLink () {
    this.userService.requestPasswordReset({ email: this.emailControl.value }).subscribe({
      next: () => {
        this.error = undefined
        this.showConfirmation('PASSWORD_RESET_LINK_SENT')
        this.resetForm()
      },
      error: (error) => {
        this.error = error.error
        this.confirmation = undefined
        this.resetErrorForm()
      }
    })
  }

  resetPassword () {
    this.userService.resetPassword({
      token: this.resetToken,
      new: this.passwordControl.value,
      repeat: this.repeatPasswordControl.value
    }).subscribe({
      next: () => {
        this.error = undefined
        this.showConfirmation('PASSWORD_SUCCESSFULLY_CHANGED')
        this.resetForm()
      },
      error: (error) => {
        this.error = error.error
        this.confirmation = undefined
        this.resetErrorForm()
      }
    })
  }

  private showConfirmation (translationKey: string) {
    this.translate.get(translationKey).subscribe({
      next: (message) => {
        this.confirmation = message
      },
      error: (translationId) => {
        this.confirmation = translationId
      }
    })
  }

  resetForm () {
    this.emailControl.setValue('')
    this.emailControl.markAsPristine()
    this.emailControl.markAsUntouched()
    this.resetErrorForm()
  }

  resetErrorForm () {
    this.emailControl.markAsPristine()
    this.emailControl.markAsUntouched()
    this.passwordControl.setValue('')
    this.passwordControl.markAsPristine()
    this.passwordControl.markAsUntouched()
    this.repeatPasswordControl.setValue('')
    this.repeatPasswordControl.markAsPristine()
    this.repeatPasswordControl.markAsUntouched()
  }
}

function matchValidator (passwordControl: AbstractControl) {
  return function matchOtherValidate (repeatPasswordControl: UntypedFormControl) {
    const password = passwordControl.value
    const passwordRepeat = repeatPasswordControl.value
    if (password !== passwordRepeat) {
      return { notSame: true }
    }
    return null
  }
}
