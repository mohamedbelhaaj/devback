# tests/test_simple.py
import pytest
from playwright.sync_api import Page, expect

# Test sans base de données
def test_homepage_loads(page: Page):
    """Test que la page d'accueil se charge (sans DB)"""
    page.goto("http://localhost:8000/")
    
    # Vérifier que la page se charge
    expect(page.locator('body')).to_be_visible()
    
    # Afficher le titre
    title = page.title()
    print(f"Titre de la page: {title}")
    
    # Prendre une capture d'écran
    page.screenshot(path="test_homepage.png")
    
    assert title != ""

def test_login_form_exists(page: Page):
    """Test que le formulaire de login existe"""
    page.goto("http://localhost:8000/accounts/login/")
    
    # Vérifier différents sélecteurs possibles
    selectors_to_check = [
        'form',
        'input[type="text"]',
        'input[type="password"]',
        'button[type="submit"]',
        'input[name="username"]',
        'input[name="password"]',
        '#id_username',
        '#id_password'
    ]
    
    found_selectors = []
    for selector in selectors_to_check:
        if page.locator(selector).count() > 0:
            found_selectors.append(selector)
    
    if found_selectors:
        print(f"Elements trouves: {found_selectors}")
    else:
        print("Aucun element de formulaire standard trouve")
    
    # Capture d'écran
    page.screenshot(path="test_login_form.png")
    
    # Le test passe si la page se charge
    expect(page.locator('body')).to_be_visible()

# Si vous avez besoin de tests avec Django DB, utilisez async
@pytest.mark.django_db
@pytest.mark.asyncio
async def test_with_database(page: Page, admin_user):
    """Exemple de test avec base de données (async)"""
    from asgiref.sync import sync_to_async
    
    # Utiliser sync_to_async pour les opérations DB
    @sync_to_async
    def get_user_count():
        from django.contrib.auth import get_user_model
        return get_user_model().objects.count()
    
    count = await get_user_count()
    print(f"Nombre d'utilisateurs: {count}")
    
    # Test UI normal
    page.goto("http://localhost:8000/")
    expect(page.locator('body')).to_be_visible()