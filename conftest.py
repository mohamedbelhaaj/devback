# conftest.py
import pytest
from django.contrib.auth import get_user_model
from playwright.sync_api import sync_playwright
from django.test import LiveServerTestCase

User = get_user_model()

@pytest.fixture(scope="session")
def django_db_setup():
    """Setup test database"""
    pass

@pytest.fixture
def live_server_url(live_server):
    """Fournit l'URL du serveur de test Django"""
    return live_server.url

@pytest.fixture
def analyst_user(db):
    """Créer un utilisateur analyste"""
    user = User.objects.create_user(
        username='analyst_test',
        email='analyst@test.com',
        password='TestPass123!',
        role='analyst',
        department='Security'
    )
    return user

@pytest.fixture
def admin_user(db):
    """Créer un utilisateur administrateur"""
    user = User.objects.create_user(
        username='admin_test',
        email='admin@test.com',
        password='AdminPass123!',
        role='admin',
        department='IT Security'
    )
    return user

@pytest.fixture
def authenticated_page(page, live_server_url, analyst_user):
    """Page Playwright avec utilisateur authentifié"""
    # Aller à la page de login
    page.goto(f"{live_server_url}/login/")
    
    # Remplir le formulaire de connexion
    page.fill('input[name="username"]', analyst_user.username)
    page.fill('input[name="password"]', 'TestPass123!')
    page.click('button[type="submit"]')
    
    # Attendre la redirection
    page.wait_for_url(f"{live_server_url}/dashboard/")
    
    return page

@pytest.fixture
def browser_context_args(browser_context_args):
    """Configuration du contexte du navigateur"""
    return {
        **browser_context_args,
        "viewport": {"width": 1920, "height": 1080},
        "ignore_https_errors": True,
    }