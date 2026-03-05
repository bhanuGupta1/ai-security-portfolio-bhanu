class InventoryPage {
  // Selectors
  get pageTitle() {
    return cy.get('[data-test="title"]');
  }

  get inventoryItems() {
    return cy.get('[data-test="inventory-item"]');
  }

  get sortDropdown() {
    return cy.get('[data-test="product-sort-container"]');
  }

  get cartBadge() {
    return cy.get('[data-test="shopping-cart-badge"]');
  }

  get cartLink() {
    return cy.get('[data-test="shopping-cart-link"]');
  }

  get burgerMenuButton() {
    return cy.get('#react-burger-menu-btn');
  }

  get logoutLink() {
    return cy.get('#logout_sidebar_link');
  }

  // Actions
  getItemByName(name) {
    return cy.contains('[data-test="inventory-item"]', name);
  }

  addItemToCartByName(name) {
    this.getItemByName(name)
      .find('button')
      .should('contain.text', 'Add to cart')
      .click();
  }

  removeItemByName(name) {
    this.getItemByName(name)
      .find('button')
      .should('contain.text', 'Remove')
      .click();
  }

  sortBy(value) {
    this.sortDropdown.select(value);
  }

  getItemNames() {
    return cy.get('[data-test="inventory-item-name"]');
  }

  getItemPrices() {
    return cy.get('[data-test="inventory-item-price"]');
  }

  goToCart() {
    this.cartLink.click();
  }

  logout() {
    this.burgerMenuButton.click();
    this.logoutLink.should('be.visible').click();
  }

  // Assertions
  verifyPageLoaded() {
    cy.url().should('include', '/inventory.html');
    this.pageTitle.should('have.text', 'Products');
  }

  verifyCartBadge(count) {
    if (count === 0) {
      cy.get('[data-test="shopping-cart-badge"]').should('not.exist');
    } else {
      this.cartBadge.should('have.text', String(count));
    }
  }

  verifyItemCount(count) {
    this.inventoryItems.should('have.length', count);
  }
}

export default new InventoryPage();
