import InventoryPage from '../pages/InventoryPage';

describe('Inventory Page', () => {
  beforeEach(() => {
    cy.loginAs('standardUser');
    InventoryPage.verifyPageLoaded();
  });

  it('TC-06: should display all 6 products on inventory page', () => {
    cy.fixture('products').then((products) => {
      InventoryPage.verifyItemCount(products.totalProductCount);
    });
  });

  it('TC-07: should display correct product names and prices', () => {
    cy.fixture('products').then((products) => {
      products.sampleProducts.forEach((product) => {
        InventoryPage.getItemByName(product.name).should('exist');
        InventoryPage.getItemByName(product.name)
          .find('[data-test="inventory-item-price"]')
          .should('have.text', product.price);
      });
    });
  });

  it('TC-08: should logout successfully', () => {
    InventoryPage.logout();
    cy.url().should('eq', 'https://www.saucedemo.com/');
  });
});
