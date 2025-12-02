"""
Script de vérification complet avant d'exécuter Locust
"""

import requests
import sys
import json
from typing import Dict, List, Tuple

# Configuration
BASE_URL = "http://127.0.0.1:8000"
TEST_USERS = [
    {"username": "test_analyst", "password": "test123", "role": "Analyst"},
    {"username": "test_admin", "password": "admin123", "role": "Admin"}
]

class Colors:
    """Codes couleurs pour le terminal"""
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def print_header(text: str):
    """Affiche un en-tête formaté"""
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*70}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.BLUE}{text.center(70)}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.BLUE}{'='*70}{Colors.RESET}\n")

def print_success(text: str):
    """Affiche un message de succès"""
    print(f"{Colors.GREEN}✅ {text}{Colors.RESET}")

def print_warning(text: str):
    """Affiche un avertissement"""
    print(f"{Colors.YELLOW}⚠️  {text}{Colors.RESET}")

def print_error(text: str):
    """Affiche une erreur"""
    print(f"{Colors.RED}❌ {text}{Colors.RESET}")

def print_info(text: str):
    """Affiche une information"""
    print(f"{Colors.BLUE}ℹ️  {text}{Colors.RESET}")

def test_server_connectivity() -> bool:
    """Test 1: Vérifier que le serveur répond"""
    print_info("Test 1: Connectivité du serveur...")
    try:
        response = requests.get(f"{BASE_URL}/", timeout=5)
        if response.status_code in [200, 404]:
            print_success(f"Serveur accessible (Status: {response.status_code})")
            return True
        else:
            print_warning(f"Serveur répond mais status inhabituel: {response.status_code}")
            return True
    except requests.exceptions.ConnectionError:
        print_error("Serveur Django non accessible")
        print_info("Lancez 'python manage.py runserver' dans un autre terminal")
        return False
    except Exception as e:
        print_error(f"Erreur inattendue: {e}")
        return False

def test_auth_endpoint_exists() -> bool:
    """Test 2: Vérifier que l'endpoint d'authentification existe"""
    print_info("Test 2: Vérification de l'endpoint d'authentification...")
    try:
        response = requests.post(
            f"{BASE_URL}/api/auth/login/",
            json={"username": "test", "password": "test"},
            timeout=5
        )
        if response.status_code == 404:
            print_error("Endpoint /api/auth/login/ non trouvé (404)")
            print_info("Vérifiez vos URLs dans virus_analyzer/urls.py")
            return False
        else:
            print_success(f"Endpoint existe (Status: {response.status_code})")
            return True
    except Exception as e:
        print_error(f"Erreur lors du test: {e}")
        return False

def test_user_login(username: str, password: str, role: str) -> Tuple[bool, str]:
    """Test 3+4: Tester la connexion d'un utilisateur"""
    print_info(f"Test: Login {role} ({username})...")
    try:
        response = requests.post(
            f"{BASE_URL}/api/auth/login/",
            json={"username": username, "password": password},
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        
        if response.status_code == 200:
            try:
                data = response.json()
                if 'access' in data:
                    print_success(f"Login {role} réussi")
                    return True, data['access']
                else:
                    print_error(f"Réponse sans token 'access': {list(data.keys())}")
                    return False, ""
            except json.JSONDecodeError:
                print_error("Réponse non-JSON reçue")
                print_info(f"Contenu: {response.text[:200]}")
                return False, ""
        else:
            print_error(f"Login échoué (Status: {response.status_code})")
            try:
                error_data = response.json()
                print_info(f"Erreur: {error_data}")
            except:
                print_info(f"Réponse: {response.text[:200]}")
            return False, ""
            
    except Exception as e:
        print_error(f"Exception lors du login: {e}")
        return False, ""

def test_protected_endpoint(token: str) -> bool:
    """Test 5: Tester l'accès à un endpoint protégé"""
    print_info("Test: Accès à un endpoint protégé...")
    try:
        response = requests.get(
            f"{BASE_URL}/api/reports/",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json"
            },
            timeout=10
        )
        
        if response.status_code in [200, 404]:
            print_success(f"Endpoint protégé accessible (Status: {response.status_code})")
            return True
        else:
            print_error(f"Accès refusé (Status: {response.status_code})")
            return False
            
    except Exception as e:
        print_error(f"Exception: {e}")
        return False

def print_django_checklist():
    """Affiche une checklist de configuration Django"""
    print_header("Checklist de Configuration Django")
    
    checklist = [
        "1. settings.py:",
        "   - DEBUG = True (pour voir les erreurs détaillées)",
        "   - ALLOWED_HOSTS = ['*'] ou ['localhost', '127.0.0.1']",
        "   - REST_FRAMEWORK configuré correctement",
        "   - SIMPLE_JWT installé et configuré",
        "",
        "2. Base de données:",
        "   - python manage.py migrate",
        "   - python create_test_users.py",
        "",
        "3. urls.py:",
        "   - path('api/auth/', include('dj_rest_auth.urls'))",
        "   - path('api/', include('vt_analyzer.urls'))",
        "",
        "4. Apps Django:",
        "   - rest_framework dans INSTALLED_APPS",
        "   - dj_rest_auth dans INSTALLED_APPS",
        "   - rest_framework_simplejwt installé",
        "",
        "5. Packages Python:",
        "   - pip install djangorestframework",
        "   - pip install djangorestframework-simplejwt",
        "   - pip install dj-rest-auth",
    ]
    
    for item in checklist:
        print(item)

def main():
    """Fonction principale"""
    print_header("🧪 PRÉ-TESTS LOCUST - VÉRIFICATION SYSTÈME")
    
    results = []
    
    # Test 1: Connectivité
    results.append(("connectivity", test_server_connectivity()))
    
    if not results[0][1]:
        print_error("\n⛔ Le serveur n'est pas accessible. Tests interrompus.")
        print_django_checklist()
        sys.exit(1)
    
    # Test 2: Endpoint auth existe
    results.append(("endpoint_exists", test_auth_endpoint_exists()))
    
    if not results[1][1]:
        print_error("\n⛔ L'endpoint d'authentification n'existe pas. Tests interrompus.")
        print_django_checklist()
        sys.exit(1)
    
    # Tests 3-4: Login des utilisateurs
    tokens = {}
    for user in TEST_USERS:
        success, token = test_user_login(user["username"], user["password"], user["role"])
        results.append((f"{user['role'].lower()}_login", success))
        if success:
            tokens[user["role"]] = token
    
    # Test 5: Endpoint protégé
    if tokens:
        first_token = list(tokens.values())[0]
        results.append(("protected_access", test_protected_endpoint(first_token)))
    else:
        results.append(("protected_access", False))
    
    # Résumé
    print_header("RÉSUMÉ DES TESTS")
    
    passed = 0
    failed = 0
    
    for name, result in results:
        if result:
            print_success(f"PASS - {name}")
            passed += 1
        else:
            print_error(f"FAIL - {name}")
            failed += 1
    
    total = len(results)
    print(f"\n{Colors.BOLD}Score: {passed}/{total} tests réussis{Colors.RESET}")
    
    if passed == total:
        print_success("\n✅ Tous les tests sont passés ! Vous pouvez lancer Locust.")
        print_info("Commande: locust -f locustfile.py --host=http://127.0.0.1:8000")
        sys.exit(0)
    else:
        print_error(f"\n❌ {failed} test(s) échoué(s). Corrigez les problèmes avant de lancer Locust.")
        print_django_checklist()
        sys.exit(1)

if __name__ == "__main__":
    main()