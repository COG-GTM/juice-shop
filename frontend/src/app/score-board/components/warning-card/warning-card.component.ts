import { Component, ChangeDetectionStrategy } from '@angular/core'

@Component({
  selector: 'warning-card',
  templateUrl: './warning-card.component.html',
  styleUrls: ['./warning-card.component.scss'],
  changeDetection: ChangeDetectionStrategy.Eager,
  standalone: true
})
export class WarningCardComponent {}
