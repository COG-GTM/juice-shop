/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import {
  waitForInputToHaveValue,
  waitForElementsTextContentToBe,
  waitInMs
} from '../helpers/helpers'
import { type ChallengeInstruction } from '../'

export const DomXssInstruction: ChallengeInstruction = {
  name: 'DOM XSS',
  hints: [
    {
      text:
        "For this challenge, we'll take a close look at the _Search_ field at the top of the screen.",
      fixture: '#product-search-fixture',
      unskippable: true,
      resolved: waitInMs(8000)
    },
    {
      text: "Let's start by searching for all products containing `owasp` in their name or description.",
      fixture: '#product-search-fixture',
      unskippable: true,
      resolved: waitForInputToHaveValue('#searchQuery input', 'owasp')
    },
    {
      text: 'Now hit enter.',
      fixture: '#product-search-fixture',
      unskippable: true,
      resolved: waitForElementsTextContentToBe('#searchValue', 'owasp')
    },
    {
      text: 'Nice! You should now see many cool OWASP-related products.',
      fixture: '#product-search-fixture',
      resolved: waitInMs(8000)
    },
    {
      text: 'You might have noticed, that your search term is displayed above the results?',
      fixture: 'app-search-result',
      resolved: waitInMs(8000)
    },
    {
      text: 'What we will try now is a **Cross-Site Scripting (XSS)** attack, where we try to inject HTML or JavaScript code into the application.',
      fixture: 'app-search-result',
      resolved: waitInMs(15000)
    },
    {
      text: 'Change your search value into `<h1>owasp` to see if we can inject HTML.',
      fixture: '#product-search-fixture',
      unskippable: true,
      resolved: waitForInputToHaveValue('#searchQuery input', '<h1>owasp')
    },
    {
      text: 'Hit enter again.',
      fixture: '#product-search-fixture',
      unskippable: true,
      resolved: waitForElementsTextContentToBe('#searchValue', '<h1>owasp')
    },
    {
      text: 'Notice that your search term is shown exactly as you typed it, including the `<h1>` tag.',
      fixture: '.noResult',
      resolved: waitInMs(8000)
    },
    {
      text: 'If you right-click on the search term and inspect that part of the page with your browser, you will see that the `h1`-tag was _not_ embedded into the page but is shown as plain text.',
      fixture: '.noResult',
      resolved: waitInMs(16000)
    },
    {
      text: "Let's see if JavaScript fares any better. Type `<script>alert(xss)</script>` into the search box now.",
      fixture: '#product-search-fixture',
      unskippable: true,
      resolved: waitForInputToHaveValue('#searchQuery input', '<script>alert(xss)</script>')
    },
    {
      text: 'Hit enter again.',
      fixture: '#product-search-fixture',
      unskippable: true,
      resolved: waitForElementsTextContentToBe('#searchValue', '<script>alert(xss)</script>')
    },
    {
      text: 'Again, the `script`-tag is only shown as text and is not executed.',
      fixture: '.noResult',
      resolved: waitInMs(10000)
    },
    {
      text: "There are _many_ different XSS payloads. Let's try this one next: <code>&lt;iframe src=\"javascript:alert(&#96;xss&#96;)\"&gt;</code>.",
      fixture: '#product-search-fixture',
      unskippable: true,
      resolved: waitForInputToHaveValue('#searchQuery input', '<iframe src="javascript:alert(`xss`)">')
    },
    {
      text: 'Hit enter one more time.',
      fixture: '#product-search-fixture',
      unskippable: true,
      resolved: waitForElementsTextContentToBe('#searchValue', '<iframe src="javascript:alert(`xss`)">')
    },
    {
      text:
        '🎉 Congratulations! You just tried a classic **Cross-Site Scripting (XSS)** payload.',
      fixture: '.noResult',
      resolved: waitInMs(8000)
    },
    {
      text:
        'This kind of attack is called **DOM XSS**, because the payload is handled by the application frontend code without even sending it to the server. Here, the search term is rendered as plain text, which keeps the payload from being embedded into the page.',
      fixture: '.noResult',
      resolved: waitInMs(16000)
    }
  ]
}
