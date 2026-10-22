/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { Component, ChangeDetectionStrategy, type OnInit, inject } from '@angular/core'
import { RouterOutlet } from '@angular/router'
import { LoginGuard } from '../app.guard'

@Component({
  standalone: true,
  selector: 'app-chatbot',
  templateUrl: './chatbot.component.html',
  styleUrls: ['./chatbot.component.scss'],
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [RouterOutlet]
})
export class ChatbotComponent implements OnInit {
  private readonly loginGuard = inject(LoginGuard)

  ngOnInit (): void {
    this.loginGuard.canActivate()
  }
}
