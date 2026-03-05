class LoginPage {
  // Selectors
  get usernameInput() {
    return cy.get('[data-test="username"]');
  }

  get passwordInput() {
    return cy.get('[data-test="password"]');
  }

  get loginButton() {
    return cy.get('[data-test="login-button"]');
  }

  get errorMessage() {
    return cy.get('[data-test="error"]');
  }

  // Actions
  visit() {
    cy.visit('/');
  }

  fillUsername(username) {
    this.usernameInput.clear().type(username);
  }

  fillPassword(password) {
    this.passwordInput.clear().type(password);
  }

  clickLogin() {
    this.loginButton.click();
  }

  login(username, password) {
    this.fillUsername(username);
    this.fillPassword(password);
    this.clickLogin();
  }

  // Assertions
  verifyErrorMessage(expectedText) {
    this.errorMessage.should('be.visible').and('contain.text', expectedText);
  }

  verifyPageLoaded() {
    cy.url().should('include', 'saucedemo.com');
    this.usernameInput.should('be.visible');
    this.passwordInput.should('be.visible');
    this.loginButton.should('be.visible');
  }
}

export default new LoginPage();
