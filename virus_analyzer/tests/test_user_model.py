import pytest
from playwright.sync_api import Page, expect

@pytest.mark.django_db
@pytest.mark.ui
class TestUserModel:
    """Tests fonctionnels UI pour le modèle User"""
    
    def test_user_registration(self, page: Page, live_server_url):
        """Test de création d'un nouvel utilisateur via l'interface"""
        page.goto(f"{live_server_url}/register/")
        
        # Remplir le formulaire d'inscription
        page.fill('input[name="username"]', 'newuser')
        page.fill('input[name="email"]', 'newuser@test.com')
        page.fill('input[name="password1"]', 'ComplexPass123!')
        page.fill('input[name="password2"]', 'ComplexPass123!')
        page.select_option('select[name="role"]', 'analyst')
        page.fill('input[name="department"]', 'Security Team')
        page.fill('input[name="phone"]', '+1234567890')
        
        # Soumettre le formulaire
        page.click('button[type="submit"]')
        
        # Vérifier la redirection et le message de succès
        expect(page).to_have_url(f"{live_server_url}/login/")
        expect(page.locator('.alert-success')).to_contain_text('Account created successfully')
    
    def test_user_login_analyst(self, page: Page, live_server_url, analyst_user):
        """Test de connexion d'un analyste"""
        page.goto(f"{live_server_url}/login/")
        
        # Remplir les identifiants
        page.fill('input[name="username"]', analyst_user.username)
        page.fill('input[name="password"]', 'TestPass123!')
        
        # Se connecter
        page.click('button[type="submit"]')
        
        # Vérifier la redirection vers le dashboard
        expect(page).to_have_url(f"{live_server_url}/dashboard/")
        expect(page.locator('.user-info')).to_contain_text('analyst_test')
    
    def test_user_login_admin(self, page: Page, live_server_url, admin_user):
        """Test de connexion d'un administrateur"""
        page.goto(f"{live_server_url}/login/")
        
        page.fill('input[name="username"]', admin_user.username)
        page.fill('input[name="password"]', 'AdminPass123!')
        page.click('button[type="submit"]')
        
        # Admin devrait avoir accès à des sections supplémentaires
        expect(page).to_have_url(f"{live_server_url}/dashboard/")
        expect(page.locator('.admin-menu')).to_be_visible()
    
    def test_user_profile_update(self, authenticated_page: Page, live_server_url):
        """Test de mise à jour du profil utilisateur"""
        authenticated_page.goto(f"{live_server_url}/profile/")
        
        # Modifier les informations
        authenticated_page.fill('input[name="department"]', 'Updated Department')
        authenticated_page.fill('input[name="phone"]', '+9876543210')
        authenticated_page.click('button[type="submit"]')
        
        # Vérifier le message de succès
        expect(authenticated_page.locator('.alert-success')).to_contain_text('Profile updated')
        
        # Vérifier que les changements sont persistés
        authenticated_page.reload()
        expect(authenticated_page.locator('input[name="department"]')).to_have_value('Updated Department')
    
    def test_user_logout(self, authenticated_page: Page, live_server_url):
        """Test de déconnexion"""
        authenticated_page.goto(f"{live_server_url}/dashboard/")
        
        # Cliquer sur le bouton de déconnexion
        authenticated_page.click('a[href="/logout/"]')
        
        # Vérifier la redirection vers la page de login
        expect(authenticated_page).to_have_url(f"{live_server_url}/login/")
        expect(authenticated_page.locator('.alert-info')).to_contain_text('logged out')
    
    def test_user_invalid_login(self, page: Page, live_server_url):
        """Test de connexion avec des identifiants invalides"""
        page.goto(f"{live_server_url}/login/")
        
        page.fill('input[name="username"]', 'wronguser')
        page.fill('input[name="password"]', 'wrongpassword')
        page.click('button[type="submit"]')
        
        # Devrait rester sur la page de login avec un message d'erreur
        expect(page).to_have_url(f"{live_server_url}/login/")
        expect(page.locator('.alert-danger')).to_contain_text('Invalid credentials')
    
    def test_user_role_display(self, authenticated_page: Page, live_server_url):
        """Test d'affichage du rôle utilisateur"""
        authenticated_page.goto(f"{live_server_url}/dashboard/")
        
        # Vérifier que le rôle est affiché
        expect(authenticated_page.locator('.user-role')).to_contain_text('Security Analyst')