describe('/profile', () => {
  beforeEach(() => {
    cy.login({ email: 'admin', password: 'admin123' })
  })
  describe('challenge "ssrf"', () => {
    it('should be possible to request internal resources using image upload URL', () => {
      cy.visit('/profile')

      cy.get('#url').type(
        `${Cypress.config('baseUrl')}/solve/challenges/server-side?key=tRy_H4rd3r_n0thIng_iS_Imp0ssibl3`
      )
      cy.get('#submitUrl').click()
      cy.visit('/')
      cy.expectChallengeSolved({ challenge: 'SSRF' })
    })
  })

  describe('challenge "usernameXss"', () => {
    it('should not execute a script tag in the username even after disarming CSP via profile image URL', () => {
      const alert = cy.stub()
      cy.on('window:alert', alert)
      cy.visit('/profile')
      cy.get('#url').type(
        "https://a.png; script-src 'unsafe-inline' 'self' 'unsafe-eval'"
      )
      cy.get('#submitUrl').click()
      cy.get('#username').type('<<a|ascript>alert(`xss`)</script>')
      cy.get('#submit').click()

      cy.get('#username').should('be.visible').then(() => {
        expect(alert).not.to.have.been.called
      })

      cy.get('#username').clear()
      cy.get('#submit').click()
      cy.get('#url').type(
        `${Cypress.config('baseUrl')}/assets/public/images/uploads/default.svg`
      )
      cy.get('#submitUrl').click()
    })
  })

  describe('challenge "ssti"', () => {
    it('should render Pug interpolation in the username as literal text', () => {
      cy.visit('/profile')
      cy.get('#username').type('a#{7*7}', { parseSpecialCharSequences: false })
      cy.get('#submit').click()

      cy.contains('p', 'a#{7*7}').should('be.visible')
      cy.contains('p', /^a49$/).should('not.exist')

      cy.get('#username').clear()
      cy.get('#submit').click()
    })
  })

  describe('challenge "csrf"', () => {
    // FIXME Only works on Chrome <80 but Protractor uses latest Chrome version. Test can probably never be turned on again.
    xit('should be possible to perform a CSRF attack against the user profile page', () => {
      cy.visit('http://htmledit.squarefree.com')
      /* The script executed below is equivalent to pasting this string into http://htmledit.squarefree.com: */
      /* <form action="http://localhost:3000/profile" method="POST"><input type="hidden" name="username" value="CSRF"/><input type="submit"/></form><script>document.forms[0].submit();</script> */
      let document: any
      cy.window().then(() => {
        document
          .getElementsByName('editbox')[0]
          .contentDocument.getElementsByName(
            'ta'
          )[0].value = `<form action=\\"${Cypress.config('baseUrl')}/profile\\" 
        method=\\"POST\\">
        <input type=\\"hidden\\" name=\\"username\\" value=\\"CSRF\\"/>
        <input type=\\"submit\\"/>
        </form>
        <script>document.forms[0].submit();
        </script>
        `
      })
      // cy.expectChallengeSolved({ challenge: 'CSRF' })
    })

    xit('should be possible to fake a CSRF attack against the user profile page', () => {
      cy.visit('/')
      cy.window().then(async () => {
        const formData = new FormData()
        formData.append('username', 'CSRF')

        const response = await fetch(`${Cypress.config('baseUrl')}/profile`, {
          method: 'POST',
          cache: 'no-cache',
          headers: {
            'Content-type': 'application/x-www-form-urlencoded',
            Authorization: `Bearer ${localStorage.getItem('token')}`,
            Origin: 'http://htmledit.squarefree.com', // FIXME Not allowed by browser due to "unsafe header not permitted"
            Cookie: `token=${localStorage.getItem('token')}` // FIXME Not allowed by browser due to "unsafe header not permitted"
          },
          body: formData
        })
        if (response.status === 200) {
          console.log('Success')
        }
      })
      // cy.expectChallengeSolved({ challenge: 'CSRF' })
    })
  })
})
