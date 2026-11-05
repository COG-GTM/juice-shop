describe('/ftp', () => {
  it('should not serve a directory listing', () => {
    cy.request({ url: '/ftp', failOnStatusCode: false }).its('body').should('not.contain', 'acquisitions.md')
  })

  it('should deny access to the confidential file /ftp/acquisitions.md', () => {
    cy.request({ url: '/ftp/acquisitions.md', failOnStatusCode: false }).its('status').should('eq', 403)
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

  for (const file of ['coupons_2013.md.bak%2500.md', 'package.json.bak%2500.md', 'eastere.gg%2500.md', 'suspicious_errors.yml%2500.md', 'encrypt.pyc%2500.md', 'incident-support.kdbx']) {
    it(`should deny access to /ftp/${file}`, () => {
      cy.request({ url: `/ftp/${file}`, failOnStatusCode: false }).its('status').should('eq', 403)
    })
  }
})
