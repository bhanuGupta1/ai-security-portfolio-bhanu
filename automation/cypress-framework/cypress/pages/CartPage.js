class CartPage {
  // Selectors
  get pageTitle() {
    return cy.get('[data-test="title"]');
  }

  get cartItems() {
    return cy.get('[data-test="inventory-item"]');
  }

  get continueShoppingButton() {
    return cy.get('[data-test="continue-shopping"]');
  }

  get checkoutButton() {
    return cy.get('[data-test="checkout"]');
  }

  // Actions
  getCartItemByName(name) {
    return cy.contains('[data-test="inventory-item"]', name);
  }

  removeItemByName(name) {
    this.getCartItemByName(name).find('button').contains('Remove').click();
  }

  continueShopping() {
    this.continueShoppingButton.click();
  }

  proceedToCheckout() {
    this.checkoutButton.click();
  }

  // Assertions
  verifyPageLoaded() {
    cy.url().should('include', '/cart.html');
    this.pageTitle.should('have.text', 'Your Cart');
  }

  verifyItemInCart(name) {
    this.getCartItemByName(name).should('exist');
  }

  verifyItemNotInCart(name) {
    cy.contains('[data-test="inventory-item"]', name).should('not.exist');
  }

  verifyCartItemCount(count) {
    if (count === 0) {
      this.cartItems.should('not.exist');
    } else {
      this.cartItems.should('have.length', count);
    }
  }

  verifyItemPrice(name, expectedPrice) {
    this.getCartItemByName(name)
      .find('[data-test="inventory-item-price"]')
      .should('have.text', expectedPrice);
  }
}

export default new CartPage();
