import requests
import json
import sys
from datetime import datetime

# Configuration
BASE_URL = "http://localhost:8000"
TIMEOUT = 5

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    END = '\033[0m'

def print_header(text):
    print(f"\n{Colors.BLUE}{'='*60}{Colors.END}")
    print(f"{Colors.BLUE}{text}{Colors.END}")
    print(f"{Colors.BLUE}{'='*60}{Colors.END}")

def print_success(text):
    print(f"{Colors.GREEN}✅ {text}{Colors.END}")

def print_error(text):
    print(f"{Colors.RED}❌ {text}{Colors.END}")

def print_warning(text):
    print(f"{Colors.YELLOW}⚠️  {text}{Colors.END}")

def print_info(text):
    print(f"ℹ️  {text}")

def test_server_connectivity():
    """Test 1: Vérifier que le serveur Django est accessible"""
    print_header("TEST 1: Connectivité serveur")
    
    try:
        response = requests.get(f"{BASE_URL}/", timeout=TIMEOUT)
        print_success(f"Serveur accessible - Status: {response.status_code}")
        return True
    except requests.exceptions.ConnectionError:
        print_error("Impossible de se connecter au serveur")
        print_info("Assurez-vous que Django est lancé: python manage.py runserver")
        return False
    except Exception as e:
        print_error(f"Erreur inattendue: {e}")
        return False

def test_login_endpoint_exists():
    """Test 2: Vérifier que l'endpoint de login existe"""
    print_header("TEST 2: Endpoint /api/auth/login/")
    
    try:
        # Essayer avec des credentials vides pour voir si l'endpoint existe
        response = requests.post(
            f"{BASE_URL}/api/auth/login/",
            json={},
            timeout=TIMEOUT
        )
        
        if response.status_code == 404:
            print_error("Endpoint non trouvé (404)")
            print_info("Vérifiez votre urls.py et les routes de l'API")
            return False
        else:
            print_success(f"Endpoint existe - Status: {response.status_code}")
            return True
            
    except Exception as e:
        print_error(f"Erreur: {e}")
        return False

def test_login_with_credentials(username, password):
    """Test 3: Tester le login avec credentials"""
    print_header(f"TEST 3: Login avec {username}")
    
    payload = {
        "username": username,
        "password": password
    }
    
    try:
        response = requests.post(
            f"{BASE_URL}/api/auth/login/",
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=TIMEOUT
        )
        
        print_info(f"Status Code: {response.status_code}")
        print_info(f"Response Headers: {dict(response.headers)}")
        
        if response.status_code == 200:
            print_success("Login réussi!")
            try:
                data = response.json()
                print_info(f"Response: {json.dumps(data, indent=2)}")
                
                if 'access' in data:
                    print_success("Token JWT reçu")
                    return True, data['access']
                else:
                    print_warning("Pas de token 'access' dans la réponse")
                    return False, None
            except json.JSONDecodeError:
                print_error("Impossible de parser la réponse JSON")
                print_info(f"Response text: {response.text}")
                return False, None
                
        elif response.status_code == 500:
            print_error("Erreur serveur 500 - C'EST LE PROBLÈME!")
            print_info("Regardez les logs Django pour voir l'erreur exacte")
            try:
                print_info(f"Response: {response.text}")
            except:
                pass
            return False, None
            
        elif response.status_code == 401:
            print_error("Credentials invalides (401)")
            print_info(f"Response: {response.text}")
            return False, None
            
        else:
            print_warning(f"Status inattendu: {response.status_code}")
            print_info(f"Response: {response.text}")
            return False, None
            
    except Exception as e:
        print_error(f"Exception: {e}")
        return False, None

def test_protected_endpoint(token):
    """Test 4: Tester un endpoint protégé avec le token"""
    print_header("TEST 4: Endpoint protégé /api/reports/")
    
    if not token:
        print_warning("Pas de token disponible, skip ce test")
        return False
    
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    try:
        response = requests.get(
            f"{BASE_URL}/api/reports/",
            headers=headers,
            timeout=TIMEOUT
        )
        
        print_info(f"Status Code: {response.status_code}")
        
        if response.status_code == 200:
            print_success("Accès autorisé!")
            return True
        elif response.status_code == 401:
            print_error("Token invalide ou expiré")
            return False
        elif response.status_code == 404:
            print_warning("Endpoint /api/reports/ non trouvé")
            return False
        else:
            print_warning(f"Status inattendu: {response.status_code}")
            return False
            
    except Exception as e:
        print_error(f"Exception: {e}")
        return False

def check_django_settings():
    """Test 5: Suggestions de vérification"""
    print_header("TEST 5: Checklist de configuration Django")
    
    print_info("Vérifiez les points suivants dans votre projet Django:")
    print("\n1. settings.py:")
    print("   - DEBUG = True (pour voir les erreurs détaillées)")
    print("   - ALLOWED_HOSTS = ['*'] ou ['localhost', '127.0.0.1']")
    print("   - REST_FRAMEWORK configuré correctement")
    print("   - SIMPLE_JWT installé et configuré")
    
    print("\n2. Base de données:")
    print("   - python manage.py migrate")
    print("   - Les utilisateurs test_analyst et test_admin existent")
    
    print("\n3. urls.py:")
    print("   - path('api/auth/', ...) est défini")
    print("   - Les routes sont correctement importées")
    
    print("\n4. Apps Django:")
    print("   - rest_framework est dans INSTALLED_APPS")
    print("   - rest_framework_simplejwt est installé")

def run_all_tests():
    """Exécuter tous les tests"""
    print(f"\n{Colors.BLUE}🔍 DIAGNOSTIC DJANGO API{Colors.END}")
    print(f"{Colors.BLUE}Temps: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.END}")
    
    results = {
        'connectivity': False,
        'endpoint_exists': False,
        'analyst_login': False,
        'admin_login': False,
        'protected_access': False
    }
    
    # Test 1: Connectivité
    results['connectivity'] = test_server_connectivity()
    if not results['connectivity']:
        print_error("\n🛑 Le serveur n'est pas accessible. Arrêt des tests.")
        return results
    
    # Test 2: Endpoint existe
    results['endpoint_exists'] = test_login_endpoint_exists()
    if not results['endpoint_exists']:
        print_error("\n🛑 L'endpoint de login n'existe pas. Arrêt des tests.")
        return results
    
    # Test 3a: Login analyste
    success, token = test_login_with_credentials("test_analyst", "test123")
    results['analyst_login'] = success
    
    # Test 3b: Login admin
    success_admin, token_admin = test_login_with_credentials("test_admin", "admin123")
    results['admin_login'] = success_admin
    
    # Test 4: Endpoint protégé (avec le premier token disponible)
    test_token = token or token_admin
    if test_token:
        results['protected_access'] = test_protected_endpoint(test_token)
    
    # Test 5: Suggestions
    check_django_settings()
    
    # Résumé
    print_header("RÉSUMÉ DES TESTS")
    total = len(results)
    passed = sum(results.values())
    
    for test_name, passed_test in results.items():
        status = "✅ PASS" if passed_test else "❌ FAIL"
        print(f"{status} - {test_name}")
    
    print(f"\n{Colors.BLUE}Score: {passed}/{total} tests réussis{Colors.END}")
    
    if passed == total:
        print_success("\n🎉 Tous les tests sont OK! Vous pouvez lancer Locust.")
    else:
        print_error("\n⚠️  Des problèmes ont été détectés. Corrigez-les avant de lancer Locust.")
    
    return results

def create_test_users_script():
    """Afficher le script pour créer les utilisateurs"""
    print_header("SCRIPT POUR CRÉER LES UTILISATEURS DE TEST")
    
    script = """
# Lancez Django shell:
python manage.py shell

# Puis copiez-collez ce code:

from django.contrib.auth import get_user_model
User = get_user_model()

# Supprimer les anciens utilisateurs de test
User.objects.filter(username__in=['test_analyst', 'test_admin']).delete()

# Créer l'analyste
analyst = User.objects.create_user(
    username='test_analyst',
    email='analyst@test.com',
    password='test123',
    is_staff=False,
    is_superuser=False
)
print(f"✅ Analyste créé: {analyst.username}")

# Créer l'admin
admin = User.objects.create_superuser(
    username='test_admin',
    email='admin@test.com',
    password='admin123'
)
print(f"✅ Admin créé: {admin.username}")

# Vérifier
print(f"Total users: {User.objects.count()}")
"""
    print(script)

if __name__ == "__main__":
    print(f"{Colors.BLUE}")
    print("=" * 60)
    print("   DIAGNOSTIC DJANGO - API DE TESTS DE CHARGE")
    print("=" * 60)
    print(f"{Colors.END}")
    
    # Demander si l'utilisateur veut voir le script de création
    print("\nOptions:")
    print("1. Lancer les tests de diagnostic")
    print("2. Afficher le script de création d'utilisateurs")
    print("3. Les deux")
    
    try:
        choice = input("\nVotre choix (1/2/3): ").strip()
        
        if choice == "1":
            run_all_tests()
        elif choice == "2":
            create_test_users_script()
        elif choice == "3":
            create_test_users_script()
            input("\nAppuyez sur Entrée pour lancer les tests...")
            run_all_tests()
        else:
            print("Choix invalide. Lancement des tests par défaut.")
            run_all_tests()
            
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}Tests interrompus par l'utilisateur{Colors.END}")
        sys.exit(0)