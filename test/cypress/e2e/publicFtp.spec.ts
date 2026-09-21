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

  describe('poison null byte', () => {
    it('should reject file names containing an encoded null byte', () => {
      cy.request({ url: '/ftp/package.json.bak%2500.md', failOnStatusCode: false }).its('status').should('equal', 403)
      cy.request({ url: '/ftp/encrypt.pyc%2500.md', failOnStatusCode: false }).its('status').should('equal', 403)
    })
  })
})
