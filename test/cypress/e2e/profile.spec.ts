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

  describe('username rendering', () => {
    it('should render a script payload in the username as inert text', () => {
      cy.task('isDocker').then((isDocker) => {
        if (!isDocker) {
          cy.visit('/profile')
          cy.get('#username').clear()
          cy.get('#username').type('<script>alert(`xss`)</script>', {
            parseSpecialCharSequences: false
          })
          cy.get('#submit').click()

          cy.get('#username').should(
            'have.value',
            '<script>alert(`xss`)</script>'
          )
          cy.document()
            .its('body')
            .then((body) => {
              expect(body.querySelectorAll('script[data-cy]')).to.have.length(0)
            })
        }
      })
    })

    it('should not evaluate a template expression in the username', () => {
      cy.task('isDocker').then((isDocker) => {
        if (!isDocker) {
          cy.visit('/profile')
          cy.get('#username').clear()
          cy.get('#username').type('#{1+1}', {
            parseSpecialCharSequences: false
          })
          cy.get('#submit').click()

          cy.get('#username').should('have.value', '#{1+1}')
          cy.contains('#{1+1}').should('exist')
        }
      })
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
