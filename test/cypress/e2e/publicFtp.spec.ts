describe('/ftp', () => {
  describe('challenge "confidentialDocument"', () => {
    it('should be able to access file /ftp/acquisitions.md', () => {
      cy.request('/ftp/acquisitions.md')
      cy.expectChallengeSolved({ challenge: 'Confidential Document' })
    })
  })

  describe('challenge "errorHandling"', () => {
    it('should leak information through error message accessing /ftp/easter.egg due to wrong file suffix', () => {
      cy.visit('/ftp/easter.egg', { failOnStatusCode: false })

      cy.get('#stacktrace').then((elements) => {
        // eslint-disable-next-line @typescript-eslint/no-unused-expressions
        expect(!!elements.length).to.be.true
      })
      cy.expectChallengeSolved({ challenge: 'Error Handling' })
    })
  })

  describe('challenge "forgottenBackup"', () => {
    it('should not be able to access /ftp/coupons_2013.md.bak with poison null byte attack', () => {
      cy.request({ url: '/ftp/coupons_2013.md.bak%2500.md', failOnStatusCode: false }).its('status').should('eq', 403)
    })
  })

  describe('challenge "forgottenDevBackup"', () => {
    it('should not be able to access /ftp/package.json.bak with poison null byte attack', () => {
      cy.request({ url: '/ftp/package.json.bak%2500.md', failOnStatusCode: false }).its('status').should('eq', 403)
    })
  })

  describe('challenge "easterEgg1"', () => {
    it('should not be able to access /ftp/eastere.gg with poison null byte attack', () => {
      cy.request({ url: '/ftp/eastere.gg%2500.md', failOnStatusCode: false }).its('status').should('eq', 403)
    })
  })

  describe('challenge "misplacedSiemFileChallenge"', () => {
    it('should not be able to access /ftp/suspicious_errors.yml with poison null byte attack', () => {
      cy.request({ url: '/ftp/suspicious_errors.yml%2500.md', failOnStatusCode: false }).its('status').should('eq', 403)
    })
  })

  describe('challenge "nullByteChallenge"', () => {
    it('should not be able to access /ftp/encrypt.pyc with poison null byte attack', () => {
      cy.request({ url: '/ftp/encrypt.pyc%2500.md', failOnStatusCode: false }).its('status').should('eq', 403)
    })
  })
})
