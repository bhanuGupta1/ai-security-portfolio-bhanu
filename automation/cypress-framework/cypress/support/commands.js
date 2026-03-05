// ***********************************************
// Custom Commands for Sauce Demo Testing
// ***********************************************

/**
 * Custom login command — reusable across all specs
 * Usage: cy.login('standard_user', 'secret_sauce')
 */
Cypress.Commands.add('login', (username, password) => {
  cy.visit('/');
  cy.get('[data-test="username"]').clear().type(username);
  cy.get('[data-test="password"]').clear().type(password);
  cy.get('[data-test="login-button"]').click();
});

/**
 * Login using fixture data
 * Usage: cy.loginAs('standardUser')
 */
Cypress.Commands.add('loginAs', (userType) => {
  cy.fixture('users').then((users) => {
    const user = users[userType];
    if (!user) throw new Error(`User type "${userType}" not found in fixtures`);
    cy.login(user.username, user.password);
  });
});

/**
 * Add a product to cart by its name from the inventory page
 * Usage: cy.addToCart('Sauce Labs Backpack')
 */
Cypress.Commands.add('addToCart', (productName) => {
  cy.contains('[data-test="inventory-item"]', productName)
    .find('button')
    .should('contain.text', 'Add to cart')
    .click();
});

/**
 * Verify the cart badge shows the expected count
 * Usage: cy.verifyCartCount(2)
 */
Cypress.Commands.add('verifyCartCount', (expectedCount) => {
  if (expectedCount === 0) {
    cy.get('[data-test="shopping-cart-badge"]').should('not.exist');
  } else {
    cy.get('[data-test="shopping-cart-badge"]').should('have.text', String(expectedCount));
  }
});
