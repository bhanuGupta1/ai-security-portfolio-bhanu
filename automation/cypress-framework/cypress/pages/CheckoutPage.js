class CheckoutPage {
  // Step One selectors
  get firstNameInput() {
    return cy.get('[data-test="firstName"]');
  }

  get lastNameInput() {
    return cy.get('[data-test="lastName"]');
  }

  get postalCodeInput() {
    return cy.get('[data-test="postalCode"]');
  }

  get continueButton() {
    return cy.get('[data-test="continue"]');
  }

  get cancelButton() {
    return cy.get('[data-test="cancel"]');
  }

  get errorMessage() {
    return cy.get('[data-test="error"]');
  }

  // Step Two selectors
  get summaryItems() {
    return cy.get('[data-test="inventory-item"]');
  }

  get subtotalLabel() {
    return cy.get('[data-test="subtotal-label"]');
  }

  get taxLabel() {
    return cy.get('[data-test="tax-label"]');
  }

  get totalLabel() {
    return cy.get('[data-test="total-label"]');
  }

  get finishButton() {
    return cy.get('[data-test="finish"]');
  }

  // Complete selectors
  get completeHeader() {
    return cy.get('[data-test="complete-header"]');
  }

  get completeText() {
    return cy.get('[data-test="complete-text"]');
  }

  get backHomeButton() {
    return cy.get('[data-test="back-to-products"]');
  }

  // Actions — Step One
  fillCheckoutInfo(firstName, lastName, postalCode) {
    if (firstName) this.firstNameInput.clear().type(firstName);
    if (lastName) this.lastNameInput.clear().type(lastName);
    if (postalCode) this.postalCodeInput.clear().type(postalCode);
  }

  clickContinue() {
    this.continueButton.click();
  }

  clickCancel() {
    this.cancelButton.click();
  }

  // Actions — Step Two
  clickFinish() {
    this.finishButton.click();
  }

  // Actions — Complete
  clickBackHome() {
    this.backHomeButton.click();
  }

  // Assertions
  verifyStepOneLoaded() {
    cy.url().should('include', '/checkout-step-one.html');
  }

  verifyStepTwoLoaded() {
    cy.url().should('include', '/checkout-step-two.html');
  }

  verifyCompleteLoaded() {
    cy.url().should('include', '/checkout-complete.html');
    this.completeHeader.should('have.text', 'Thank you for your order!');
  }

  verifyErrorMessage(expectedText) {
    this.errorMessage.should('be.visible').and('contain.text', expectedText);
  }

  verifySummaryItemCount(count) {
    this.summaryItems.should('have.length', count);
  }

  verifyTotalExists() {
    this.totalLabel.should('be.visible');
  }
}

export default new CheckoutPage();
