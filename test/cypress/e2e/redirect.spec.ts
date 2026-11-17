describe('/redirect', () => {
  describe('challenge "redirect"', () => {
    it('should show a generic error when supplying an unrecognized target URL', () => {
      cy.request({ url: '/redirect?to=http://kimminich.de', failOnStatusCode: false }).then((response) => {
        expect(response.status).to.equal(406)
        expect(response.body).to.deep.equal({ error: 'Not Acceptable' })
      })
    })
  })

  describe('challenge "redirect"', () => {
    it('should redirect to target URL if allowlisted URL is contained in it as parameter', () => {
      cy.visit(
        '/redirect?to=https://owasp.org?trickIndexOf=https://github.com/juice-shop/juice-shop',
        {
          failOnStatusCode: false
        }
      )
      cy.url().should('match', /https:\/\/owasp\.org/)
      cy.expectChallengeSolved({ challenge: 'Allowlist Bypass' })
    })
  })

  describe('challenge "redirectCryptoCurrency"', () => {
    it('should still redirect to forgotten entry https://etherscan.io/address/0x0f933ab9fcaaa782d0279c300d73750e1311eae6 on allowlist', () => {
      cy.visit(
        '/redirect?to=https://etherscan.io/address/0x0f933ab9fcaaa782d0279c300d73750e1311eae6',
        {
          failOnStatusCode: false
        }
      )
      cy.expectChallengeSolved({ challenge: 'Outdated Allowlist' })
    })
  })
})
