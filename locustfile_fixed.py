from locust import HttpUser, task, between, TaskSet, events
import random
import json
import logging

# Configuration du logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ===================================================================
# UTILS
# ===================================================================

class TestDataGenerator:
    """Générateur de données de test"""
    
    @staticmethod
    def get_random_ip():
        return f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}"
    
    @staticmethod
    def get_random_hash():
        return "".join(random.choice("abcdef0123456789") for _ in range(32))
    
    @staticmethod
    def get_random_domain():
        domains = ["test-malicious.com", "test-phishing.org", "test-suspicious.net"]
        return random.choice(domains)
    
    @staticmethod
    def get_random_url():
        protocols = ["http://", "https://"]
        domains = ["test-evil.com/payload", "test-phishing.org/login"]
        return random.choice(protocols) + random.choice(domains)
    
    @staticmethod
    def get_random_engine():
        return random.choice(["vt", "otx"])

# ===================================================================
# TASKS POUR ANALYSTES
# ===================================================================

class AnalystTasks(TaskSet):
    """Tâches pour tester les endpoints des analystes"""
    
    def on_start(self):
        """Connexion de l'analyste avec retry"""
        max_retries = 3
        for attempt in range(max_retries):
            if self.login("test_analyst", "test123"):
                logger.info(f"✅ Analyste connecté après {attempt + 1} tentative(s)")
                return
            logger.warning(f"⚠️ Tentative {attempt + 1}/{max_retries} échouée")
        
        logger.error("❌ Impossible de connecter l'analyste après 3 tentatives")
        self.interrupt()
    
    def login(self, username, password):
        """Méthode de connexion corrigée"""
        try:
            # CORRECTION: Utiliser with-block pour catch_response
            with self.client.post(
                "/api/auth/login/", 
                json={"username": username, "password": password},
                name="POST /api/auth/login/ [Analyst]",
                timeout=10,
                catch_response=True
            ) as response:
                
                if response.status_code == 200:
                    data = response.json()
                    self.user.token = data.get('access')
                    self.user.headers = {
                        "Authorization": f"Bearer {self.user.token}",
                        "Content-Type": "application/json"
                    }
                    response.success()
                    return True
                else:
                    logger.error(f"❌ Login failed: {response.status_code}")
                    logger.error(f"Response: {response.text[:200]}")
                    response.failure(f"Login failed with status {response.status_code}")
                    return False
                
        except Exception as e:
            logger.error(f"❌ Exception during login: {str(e)}")
            return False
    
    @task(4)
    def analyze_threat(self):
        """Tester /api/analyze/"""
        if not hasattr(self.user, 'headers') or not self.user.headers:
            logger.warning("⚠️ Non authentifié, skip analyse")
            return
        
        threat_types = [
            {
                "input_value": TestDataGenerator.get_random_ip(),
                "engine_choice": TestDataGenerator.get_random_engine()
            },
            {
                "input_value": TestDataGenerator.get_random_url(),
                "engine_choice": TestDataGenerator.get_random_engine()
            },
            {
                "input_value": TestDataGenerator.get_random_hash(),
                "engine_choice": TestDataGenerator.get_random_engine()
            }
        ]
        
        payload = random.choice(threat_types)
        
        try:
            with self.client.post(
                "/api/analyze/", 
                json=payload,
                headers=self.user.headers,
                name="POST /api/analyze/",
                catch_response=True,
                timeout=30
            ) as response:
                if response.status_code in [200, 201]:
                    response.success()
                    try:
                        data = response.json()
                        report_id = data.get('id')
                        if report_id:
                            if not hasattr(self.user, 'last_report_ids'):
                                self.user.last_report_ids = []
                            self.user.last_report_ids.append(report_id)
                    except json.JSONDecodeError:
                        logger.warning("⚠️ Impossible de parser la réponse JSON")
                else:
                    response.failure(f"Status: {response.status_code}")
                    logger.error(f"Analyse failed: {response.text[:200]}")
        except Exception as e:
            logger.error(f"❌ Exception during analyze: {str(e)}")
    
    @task(3)
    def view_my_reports(self):
        """Tester /api/reports/"""
        if not hasattr(self.user, 'headers') or not self.user.headers:
            return
        
        try:
            self.client.get(
                "/api/reports/", 
                headers=self.user.headers,
                name="GET /api/reports/",
                timeout=10
            )
        except Exception as e:
            logger.error(f"❌ Error viewing reports: {str(e)}")
    
    @task(2)
    def view_notifications(self):
        """Tester /api/notifications/"""
        if not hasattr(self.user, 'headers') or not self.user.headers:
            return
        
        try:
            self.client.get(
                "/api/notifications/", 
                headers=self.user.headers,
                name="GET /api/notifications/",
                timeout=10
            )
        except Exception as e:
            logger.error(f"❌ Error viewing notifications: {str(e)}")
    
    @task(1)
    def view_tasks(self):
        """Tester /api/tasks/"""
        if not hasattr(self.user, 'headers') or not self.user.headers:
            return
        
        try:
            self.client.get(
                "/api/tasks/", 
                headers=self.user.headers,
                name="GET /api/tasks/",
                timeout=10
            )
        except Exception as e:
            logger.error(f"❌ Error viewing tasks: {str(e)}")

# ===================================================================
# TASKS POUR ADMINS
# ===================================================================

class AdminTasks(TaskSet):
    """Tâches pour tester les endpoints des administrateurs"""
    
    def on_start(self):
        """Connexion de l'admin avec retry"""
        max_retries = 3
        for attempt in range(max_retries):
            if self.login("test_admin", "admin123"):
                logger.info(f"✅ Admin connecté après {attempt + 1} tentative(s)")
                return
            logger.warning(f"⚠️ Tentative {attempt + 1}/{max_retries} échouée")
        
        logger.error("❌ Impossible de connecter l'admin après 3 tentatives")
        self.interrupt()
    
    def login(self, username, password):
        """Méthode de connexion corrigée"""
        try:
            # CORRECTION: Utiliser with-block pour catch_response
            with self.client.post(
                "/api/auth/login/", 
                json={"username": username, "password": password},
                name="POST /api/auth/login/ [Admin]",
                timeout=10,
                catch_response=True
            ) as response:
                
                if response.status_code == 200:
                    data = response.json()
                    self.user.token = data.get('access')
                    self.user.headers = {
                        "Authorization": f"Bearer {self.user.token}",
                        "Content-Type": "application/json"
                    }
                    response.success()
                    return True
                else:
                    logger.error(f"❌ Admin login failed: {response.status_code}")
                    logger.error(f"Response: {response.text[:200]}")
                    response.failure(f"Admin login failed with status {response.status_code}")
                    return False
                
        except Exception as e:
            logger.error(f"❌ Exception during admin login: {str(e)}")
            return False
    
    @task(5)
    def view_admin_dashboard(self):
        """Tester /api/admin/dashboard/"""
        if not hasattr(self.user, 'headers') or not self.user.headers:
            return
        
        try:
            self.client.get(
                "/api/admin/dashboard/", 
                headers=self.user.headers,
                name="GET /api/admin/dashboard/",
                timeout=10
            )
        except Exception as e:
            logger.error(f"❌ Error accessing dashboard: {str(e)}")
    
    @task(4)
    def view_admin_reports(self):
        """Tester /api/admin/reports/"""
        if not hasattr(self.user, 'headers') or not self.user.headers:
            return
        
        filters = ["", "?severity=critical", "?status=pending"]
        filter_param = random.choice(filters)
        
        try:
            self.client.get(
                f"/api/admin/reports/{filter_param}", 
                headers=self.user.headers,
                name=f"GET /api/admin/reports/",
                timeout=10
            )
        except Exception as e:
            logger.error(f"❌ Error viewing admin reports: {str(e)}")
    
    @task(3)
    def check_aws_status(self):
        """Tester /api/aws/status/"""
        if not hasattr(self.user, 'headers') or not self.user.headers:
            return
        
        try:
            self.client.get(
                "/api/admin/aws-status/", 
                headers=self.user.headers,
                name="GET /api/admin/aws-status/",
                timeout=10
            )
        except Exception as e:
            logger.error(f"❌ Error checking AWS status: {str(e)}")
    
    @task(2)
    def view_threat_analytics(self):
        """Tester /api/analytics/"""
        if not hasattr(self.user, 'headers') or not self.user.headers:
            return
        
        periods = ["", "?days=7", "?days=30"]
        period = random.choice(periods)
        
        try:
            self.client.get(
                f"/api/analytics/{period}", 
                headers=self.user.headers,
                name=f"GET /api/analytics/",
                timeout=10
            )
        except Exception as e:
            logger.error(f"❌ Error viewing analytics: {str(e)}")

# ===================================================================
# TASKS POUR UTILISATEURS NON AUTHENTIFIÉS
# ===================================================================

class PublicTasks(TaskSet):
    """Tâches pour endpoints publics"""
    
    @task(3)
    def login_attempt(self):
        """Tenter de se connecter"""
        users = [
            {"username": "test_analyst", "password": "test123"},
            {"username": "test_admin", "password": "admin123"},
            {"username": "wrong_user", "password": "wrong_pass"}
        ]
        
        user = random.choice(users)
        
        try:
            self.client.post(
                "/api/auth/login/", 
                json=user,
                name="POST /api/auth/login/ [Public]",
                timeout=10
            )
        except Exception as e:
            logger.error(f"❌ Public login error: {str(e)}")
    
    @task(1)
    def access_homepage(self):
        """Accéder à la page d'accueil"""
        try:
            self.client.get(
                "/", 
                name="GET / [Homepage]",
                timeout=10
            )
        except Exception as e:
            logger.error(f"❌ Homepage access error: {str(e)}")

# ===================================================================
# CLASSES UTILISATEURS LOCUST
# ===================================================================

class AnalystUser(HttpUser):
    """Utilisateur analyste"""
    wait_time = between(2, 5)
    tasks = [AnalystTasks]
    weight = 5
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.headers = None
        self.token = None

class AdminUser(HttpUser):
    """Utilisateur administrateur"""
    wait_time = between(3, 8)
    tasks = [AdminTasks]
    weight = 2
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.headers = None
        self.token = None

class PublicUser(HttpUser):
    """Utilisateur public (non authentifié)"""
    wait_time = between(1, 3)
    tasks = [PublicTasks]
    weight = 1

# ===================================================================
# HOOKS ET CONFIGURATION
# ===================================================================

@events.test_start.add_listener
def on_test_start(environment, **kwargs):
    print("=" * 60)
    print("🧪 DÉBUT DES TESTS DE PERFORMANCE")
    print("=" * 60)
    print(f"Host: {environment.host}")
    
    if hasattr(environment, 'parsed_options'):
        print(f"Nombre d'utilisateurs: {environment.parsed_options.num_users}")
        print(f"Spawn rate: {environment.parsed_options.spawn_rate}")
    
    print("=" * 60)
    
    # Vérifier que l'API est accessible
    import requests
    try:
        response = requests.get(f"{environment.host}/", timeout=5)
        if response.status_code == 200:
            print("✅ Serveur Django accessible")
        else:
            print(f"⚠️ Serveur répond avec: {response.status_code}")
    except Exception as e:
        print(f"❌ Serveur non accessible: {e}")
        print("⚠️ Assurez-vous que Django est lancé sur le bon port")

@events.test_stop.add_listener
def on_test_stop(environment, **kwargs):
    print("=" * 60)
    print("🏁 FIN DES TESTS DE PERFORMANCE")
    print("=" * 60)
    
    # Afficher les statistiques si disponibles
    if hasattr(environment, 'stats'):
        print(f"Total de requêtes: {environment.stats.total.num_requests}")
        print(f"Requêtes échouées: {environment.stats.total.num_failures}")