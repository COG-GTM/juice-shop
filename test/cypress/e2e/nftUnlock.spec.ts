describe('/#/juicy-nft', () => {
  describe('challenge "nftUnlock"', () => {
    it('should be possible to unlock the NFT with the private key derived from the leaked seed phrase', () => {
      cy.task<string>('GetNftWalletPrivateKey').then((privateKey: string) => {
        cy.visit('/#/juicy-nft')
        cy.get('#privateKey').type(privateKey, { log: false })
        cy.get('#privateKey').parents('form').find('button[type="submit"]').click()
        cy.expectChallengeSolved({ challenge: 'NFT Takeover' })
      })
    })
  })
})
