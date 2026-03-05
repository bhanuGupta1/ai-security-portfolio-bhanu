import InventoryPage from '../pages/InventoryPage';
import CartPage from '../pages/CartPage';

describe('Shopping Cart', () => {
  beforeEach(() => {
    cy.loginAs('standardUser');
    InventoryPage.verifyPageLoaded();
  });

  it('TC-09: should add a single item to cart and verify badge', () => {
    InventoryPage.addItemToCartByName('Sauce Labs Backpack');
    InventoryPage.verifyCartBadge(1);
  });

  it('TC-10: should add multiple items and verify cart badge updates', () => {
    InventoryPage.addItemToCartByName('Sauce Labs Backpack');
    InventoryPage.addItemToCartByName('Sauce Labs Bike Light');
    InventoryPage.verifyCartBadge(2);
  });

  it('TC-11: should remove item from cart on inventory page', () => {
    InventoryPage.addItemToCartByName('Sauce Labs Backpack');
    InventoryPage.verifyCartBadge(1);
    InventoryPage.removeItemByName('Sauce Labs Backpack');
    InventoryPage.verifyCartBadge(0);
  });

  it('TC-12: should show added items in cart page with correct prices', () => {
    InventoryPage.addItemToCartByName('Sauce Labs Backpack');
    InventoryPage.addItemToCartByName('Sauce Labs Onesie');
    InventoryPage.goToCart();

    CartPage.verifyPageLoaded();
    CartPage.verifyCartItemCount(2);
    CartPage.verifyItemInCart('Sauce Labs Backpack');
    CartPage.verifyItemPrice('Sauce Labs Backpack', '$29.99');
    CartPage.verifyItemInCart('Sauce Labs Onesie');
    CartPage.verifyItemPrice('Sauce Labs Onesie', '$7.99');
  });

  it('TC-13: should remove item from cart page', () => {
    InventoryPage.addItemToCartByName('Sauce Labs Backpack');
    InventoryPage.addItemToCartByName('Sauce Labs Bike Light');
    InventoryPage.goToCart();

    CartPage.verifyCartItemCount(2);
    CartPage.removeItemByName('Sauce Labs Backpack');
    CartPage.verifyCartItemCount(1);
    CartPage.verifyItemNotInCart('Sauce Labs Backpack');
    CartPage.verifyItemInCart('Sauce Labs Bike Light');
  });

  it('TC-14: should return to inventory from cart via Continue Shopping', () => {
    InventoryPage.goToCart();
    CartPage.verifyPageLoaded();
    CartPage.continueShopping();
    InventoryPage.verifyPageLoaded();
  });
});
