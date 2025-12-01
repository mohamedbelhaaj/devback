import subprocess
import sys
import os
import argparse
from pathlib import Path
import time
import webbrowser

def setup_test_environment():
    """Configurer l'environnement de test"""
    print("🔧 Configuration de l'environnement de test...")
    
    # Vérifier si Playwright est installé
    try:
        result = subprocess.run(['playwright', '--version'], 
                              capture_output=True, 
                              text=True,
                              check=True)
        print(f"✓ Playwright version: {result.stdout.strip()}")
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("📦 Installation de Playwright...")
        try:
            subprocess.run([sys.executable, '-m', 'pip', 'install', 'pytest-playwright'], 
                         check=True, capture_output=True)
            subprocess.run(['playwright', 'install', 'chromium'], check=False)
            print("✓ Playwright installé avec succès")
        except subprocess.CalledProcessError as e:
            print(f"❌ Erreur d'installation: {e}")
            return False
    
    # Vérifier si pytest est installé
    try:
        subprocess.run(['pytest', '--version'], capture_output=True, check=True)
        print("✓ pytest est installé")
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("📦 Installation de pytest...")
        subprocess.run([sys.executable, '-m', 'pip', 'install', 'pytest'], check=True)
    
    # Créer la structure de dossiers de tests si elle n'existe pas
    tests_dir = Path('tests')
    if not tests_dir.exists():
        print("📁 Création de la structure des dossiers de tests...")
        tests_dir.mkdir(exist_ok=True)
        
        # Créer les sous-dossiers
        subdirs = ['auth', 'reports', 'mitigation', 'tasks', 'utils', 'export']
        for subdir in subdirs:
            (tests_dir / subdir).mkdir(exist_ok=True)
        
        # Créer __init__.py dans chaque dossier
        for dir_path in tests_dir.rglob(''):
            if dir_path.is_dir():
                (dir_path / '__init__.py').touch(exist_ok=True)
        
        print("📝 Création des fichiers de test de base...")
        # Créer un fichier de test de base
        basic_test = tests_dir / 'test_basic.py'
        if not basic_test.exists():
            with open(basic_test, 'w', encoding='utf-8') as f:
                f.write('''"""
Test basique pour vérifier que l'application fonctionne
"""
import pytest
from playwright.sync_api import Page, expect

def test_homepage_loads(page: Page):
    """Test que la page d'accueil se charge"""
    page.goto("http://localhost:8000/")
    
    # Vérifier les éléments de base
    expect(page.locator('body')).to_be_visible()
    
    # Vérifier le titre ou un élément spécifique
    title = page.title()
    print(f"✓ Page chargée: {title}")
    
    # Prendre une capture d'écran
    page.screenshot(path="tests/screenshots/homepage.png")
    print("✓ Capture d'écran sauvegardée")

def test_login_page_exists(page: Page):
    """Test que la page de login existe"""
    page.goto("http://localhost:8000/accounts/login/")
    
    # Vérifier les éléments de la page de login
    expect(page.locator('input[name="username"], #id_username')).to_be_visible()
    expect(page.locator('input[type="password"], #id_password')).to_be_visible()
    print("✓ Page de login chargée")
''')
        
        # Créer conftest.py
        conftest_file = tests_dir / 'conftest.py'
        if not conftest_file.exists():
            with open(conftest_file, 'w', encoding='utf-8') as f:
                f.write('''import pytest
import os
import django
from django.conf import settings

# Initialiser Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'vt_analyzer.settings')

try:
    django.setup()
except Exception as e:
    print(f"Note: Django setup failed: {e}")

@pytest.fixture(scope='session')
def django_db_setup():
    """Setup Django database for tests"""
    settings.DATABASES['default'] = {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': ':memory:',
    }

@pytest.fixture
def admin_user(django_db_setup):
    """Create admin user for tests"""
    from django.contrib.auth import get_user_model
    User = get_user_model()
    
    user, created = User.objects.get_or_create(
        username='admin_test',
        defaults={
            'email': 'admin@test.com',
            'is_staff': True,
            'is_superuser': True
        }
    )
    if created:
        user.set_password('testpassword123')
        user.save()
    return user

@pytest.fixture
def analyst_user(django_db_setup):
    """Create analyst user for tests"""
    from django.contrib.auth import get_user_model
    User = get_user_model()
    
    user, created = User.objects.get_or_create(
        username='analyst_test',
        defaults={
            'email': 'analyst@test.com',
            'is_staff': False,
            'is_superuser': False
        }
    )
    if created:
        user.set_password('testpassword123')
        user.save()
    return user
''')
    
    # Créer le dossier screenshots
    screenshots_dir = tests_dir / 'screenshots'
    screenshots_dir.mkdir(exist_ok=True)
    
    print("✅ Environnement de test configuré avec succès")
    return True

def create_sample_tests():
    """Créer des exemples de tests pour chaque module"""
    print("\n📄 Création des exemples de tests...")
    
    # Test d'authentification
    auth_test = Path('tests/auth/test_login.py')
    if not auth_test.exists():
        auth_test.parent.mkdir(exist_ok=True)
        with open(auth_test, 'w', encoding='utf-8') as f:
            f.write('''import pytest
from playwright.sync_api import Page, expect

def test_successful_login(page: Page):
    """Test de connexion réussie"""
    page.goto("http://localhost:8000/accounts/login/")
    
    # Remplir le formulaire
    page.fill('input[name="username"]', 'admin_test')
    page.fill('input[name="password"]', 'testpassword123')
    page.click('button[type="submit"]')
    
    # Vérifier la redirection
    expect(page).to_have_url(re.compile(r'.*/dashboard/|.*/reports/'))
    print("✓ Connexion réussie")

def test_invalid_login(page: Page):
    """Test de connexion échouée"""
    page.goto("http://localhost:8000/accounts/login/")
    
    page.fill('input[name="username"]', 'invalid_user')
    page.fill('input[name="password"]', 'wrong_password')
    page.click('button[type="submit"]')
    
    # Vérifier le message d'erreur
    expect(page.locator('.error, .alert-danger')).to_be_visible()
    print("✓ Test d'erreur de connexion réussi")
''')
    
    # Test des rapports
    reports_test = Path('tests/reports/test_reports.py')
    if not reports_test.exists():
        reports_test.parent.mkdir(exist_ok=True)
        with open(reports_test, 'w', encoding='utf-8') as f:
            f.write('''import pytest
from playwright.sync_api import Page, expect
import re

@pytest.mark.django_db
def test_create_report(page: Page):
    """Test de création de rapport"""
    # D'abord se connecter
    page.goto("http://localhost:8000/accounts/login/")
    page.fill('input[name="username"]', 'admin_test')
    page.fill('input[name="password"]', 'testpassword123')
    page.click('button[type="submit"]')
    
    # Aller à la création de rapport
    page.goto("http://localhost:8000/reports/create/")
    
    # Vérifier le formulaire
    expect(page.locator('form')).to_be_visible()
    print("✓ Formulaire de création de rapport chargé")
    
    # Remplir le formulaire (si les champs existent)
    page.fill('input[name="input_value"]', '8.8.8.8')
    page.select_option('select[name="input_type"]', 'ip')
    
    # Prendre une capture d'écran
    page.screenshot(path="tests/screenshots/report_form.png")

def test_report_list(page: Page):
    """Test de la liste des rapports"""
    page.goto("http://localhost:8000/reports/")
    
    # Vérifier que la page se charge
    expect(page.locator('body')).to_be_visible()
    
    # Chercher des éléments communs
    expect(page.locator('h1, h2')).to_contain_text(['Reports', 'Rapports'], ignore_case=True)
    print("✓ Liste des rapports chargée")
''')
    
    print("✅ Exemples de tests créés")

def start_django_server(port=8000):
    """Démarrer le serveur Django en arrière-plan"""
    print(f"\n🚀 Démarrage du serveur Django sur le port {port}...")
    
    # Vérifier si le serveur est déjà en cours d'exécution
    try:
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex(('localhost', port))
        sock.close()
        
        if result == 0:
            print(f"⚠ Le serveur est déjà en cours d'exécution sur le port {port}")
            return None
    except:
        pass
    
    # Démarrer le serveur
    try:
        # Sous Windows
        if os.name == 'nt':
            server_process = subprocess.Popen(
                [sys.executable, 'manage.py', 'runserver', f'{port}'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP
            )
        else:
            # Sous Linux/Mac
            server_process = subprocess.Popen(
                [sys.executable, 'manage.py', 'runserver', f'{port}'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True
            )
        
        # Attendre que le serveur démarre
        print("⏳ Attente du démarrage du serveur...")
        time.sleep(5)
        
        # Vérifier si le serveur est en cours d'exécution
        try:
            import requests
            response = requests.get(f'http://localhost:{port}/', timeout=5)
            if response.status_code < 500:
                print(f"✅ Serveur Django démarré sur http://localhost:{port}")
                return server_process
        except:
            print("⚠ Impossible de vérifier le serveur, continuation...")
            return server_process
            
    except Exception as e:
        print(f"❌ Erreur lors du démarrage du serveur: {e}")
        return None
    
    return server_process

def stop_django_server(process):
    """Arrêter le serveur Django"""
    if process:
        print("\n🛑 Arrêt du serveur Django...")
        try:
            if os.name == 'nt':
                # Windows
                subprocess.run(['taskkill', '/F', '/T', '/PID', str(process.pid)], 
                             capture_output=True)
            else:
                # Linux/Mac
                process.terminate()
                process.wait(timeout=10)
            print("✅ Serveur arrêté")
        except:
            print("⚠ Impossible d'arrêter le serveur proprement")

def run_tests(test_path=None, browser=None, headed=False, slowmo=None, 
             create_report=False, open_report=False):
    """Exécuter les tests avec différentes options"""
    
    cmd = ['pytest']
    
    if test_path:
        if os.path.exists(test_path):
            cmd.append(test_path)
        else:
            print(f"❌ Chemin de test non trouvé: {test_path}")
            return 1
    else:
        cmd.append('tests/')
    
    # Options de Playwright
    if headed:
        cmd.append('--headed')
    
    if slowmo:
        cmd.extend(['--slowmo', str(slowmo)])
    
    # Options de rapport
    if create_report:
        cmd.extend([
            '--html=playwright-report/report.html',
            '--self-contained-html'
        ])
    
    # Options générales
    cmd.extend([
        '-v',  # Verbose
        '--tb=short',  # Short traceback
        '--capture=no',  # Afficher les prints
    ])
    
    # Créer le dossier de rapport si nécessaire
    if create_report:
        Path('playwright-report').mkdir(exist_ok=True)
    
    print(f"\n🚀 Exécution de la commande: {' '.join(cmd)}")
    print("-" * 60)
    
    try:
        # Exécuter les tests
        result = subprocess.run(cmd, capture_output=False, text=True)
        
        # Ouvrir le rapport si demandé
        if open_report and create_report and Path('playwright-report/report.html').exists():
            print("\n📊 Ouverture du rapport...")
            webbrowser.open('file://' + os.path.abspath('playwright-report/report.html'))
        
        return result.returncode
        
    except KeyboardInterrupt:
        print("\n⏹️ Tests interrompus par l'utilisateur")
        return 130
    except Exception as e:
        print(f"\n❌ Erreur lors de l'exécution des tests: {e}")
        return 1

def list_available_tests():
    """Lister tous les tests disponibles"""
    print("\n📋 Tests disponibles:")
    print("-" * 40)
    
    tests_dir = Path('tests')
    if not tests_dir.exists():
        print("Aucun test trouvé. Exécutez --setup pour créer la structure.")
        return
    
    test_count = 0
    for test_file in sorted(tests_dir.rglob('test_*.py')):
        rel_path = test_file.relative_to(tests_dir)
        print(f"  • {rel_path}")
        test_count += 1
    
    for test_file in sorted(tests_dir.rglob('*.py')):
        if test_file.name.startswith('test_'):
            continue
        if test_file.name != '__init__.py':
            rel_path = test_file.relative_to(tests_dir)
            print(f"  • {rel_path} (non-test)")
    
    print(f"\nTotal: {test_count} fichiers de test trouvés")

def main():
    """Fonction principale"""
    parser = argparse.ArgumentParser(
        description='Exécuter les tests Playwright pour VT Analyzer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Exemples:
  %(prog)s                    # Exécuter tous les tests
  %(prog)s --headed           # Exécuter en mode visible
  %(prog)s --path tests/auth/ # Exécuter tests d'auth
  %(prog)s --setup            # Configurer l'environnement
  %(prog)s --sample           # Créer des exemples de tests
        '''
    )
    
    parser.add_argument('--path', help='Chemin spécifique des tests à exécuter')
    parser.add_argument('--browser', choices=['chromium', 'firefox', 'webkit'], 
                       default='chromium', help='Navigateur à utiliser')
    parser.add_argument('--headed', action='store_true', 
                       help='Exécuter en mode visible (avec fenêtre)')
    parser.add_argument('--slowmo', type=int, default=100, 
                       help='Délai entre les actions (ms)')
    parser.add_argument('--port', type=int, default=8000,
                       help='Port du serveur Django')
    parser.add_argument('--no-server', action='store_true',
                       help='Ne pas démarrer le serveur (suppose qu\'il est déjà en cours d\'exécution)')
    parser.add_argument('--report', action='store_true',
                       help='Générer un rapport HTML')
    parser.add_argument('--open-report', action='store_true',
                       help='Ouvrir le rapport après les tests')
    parser.add_argument('--setup', action='store_true',
                       help='Configurer seulement l\'environnement')
    parser.add_argument('--sample', action='store_true',
                       help='Créer des exemples de tests')
    parser.add_argument('--list', action='store_true',
                       help='Lister les tests disponibles')
    parser.add_argument('--interactive', action='store_true',
                       help='Mode interactif avec questions')
    
    args = parser.parse_args()
    
    print("\n" + "="*60)
    print("🧪 VT ANALYZER - SUITE DE TESTS PLAYWRIGHT")
    print("="*60)
    
    # Mode interactif
    if args.interactive:
        print("\n🎮 Mode interactif")
        print("-" * 40)
        
        response = input("Configurer l'environnement? (o/n): ").lower()
        if response == 'o':
            args.setup = True
        
        response = input("Créer des exemples de tests? (o/n): ").lower()
        if response == 'o':
            args.sample = True
        
        response = input("Exécuter en mode visible? (o/n): ").lower()
        if response == 'o':
            args.headed = True
        
        response = input("Générer un rapport HTML? (o/n): ").lower()
        if response == 'o':
            args.report = True
    
    # Configuration de l'environnement
    if args.setup:
        if not setup_test_environment():
            return 1
    
    # Création d'exemples de tests
    if args.sample:
        create_sample_tests()
    
    # Lister les tests
    if args.list:
        list_available_tests()
        return 0
    
    # Si seulement setup ou sample, s'arrêter ici
    if args.setup and not (args.path or args.interactive):
        return 0
    
    # Démarrer le serveur Django si nécessaire
    server_process = None
    if not args.no_server:
        server_process = start_django_server(args.port)
        if not server_process:
            print("❌ Impossible de démarrer le serveur Django")
            return 1
    
    try:
        # Exécuter les tests
        return_code = run_tests(
            test_path=args.path,
            headed=args.headed,
            slowmo=args.slowmo,
            create_report=args.report,
            open_report=args.open_report
        )
        
        print("\n" + "="*60)
        if return_code == 0:
            print("✅ TOUS LES TESTS RÉUSSIS!")
        else:
            print(f"❌ TESTS TERMINÉS AVEC CODE: {return_code}")
        print("="*60)
        
        return return_code
        
    finally:
        # Toujours arrêter le serveur
        stop_django_server(server_process)

if __name__ == '__main__':
    try:
        exit_code = main()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n\n⏹️ Script interrompu par l'utilisateur")
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ Erreur inattendue: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1) 