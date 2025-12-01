import pytest
from playwright.sync_api import Page, expect
import re

@pytest.mark.django_db
def test_homepage_loads(page: Page, live_server):
    """Test que la page d'accueil se charge"""
    page.goto(f"{live_server.url}/")
    
    # Vérifier les éléments de base
    expect(page.locator('body')).to_be_visible()
    
    # Vérifier le titre ou un élément spécifique
    title = page.title()
    print(f"✓ Page chargée: {title}")
    
    # Prendre une capture d'écran
    page.screenshot(path="tests/screenshots/homepage.png")

@pytest.mark.django_db
def test_login_page_exists(page: Page, live_server):
    """Test que la page de login existe"""
    page.goto(f"{live_server.url}/accounts/login/")
    
    # Vérifier les éléments de la page de login
    expect(page.locator('form')).to_be_visible()
    
    # Chercher différents sélecteurs possibles
    username_selectors = ['input[name="username"]', '#id_username', 'input[type="text"]']
    password_selectors = ['input[name="password"]', '#id_password', 'input[type="password"]']
    
    for selector in username_selectors + password_selectors:
        if page.locator(selector).count() > 0:
            print(f"✓ Élément trouvé: {selector}")
    
    print("✓ Page de login chargée")
    page.screenshot(path="tests/screenshots/login_page.png")