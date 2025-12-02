import os
from pathlib import Path
import dj_database_url
from dotenv import load_dotenv
from datetime import timedelta
import sys  # Ajout pour détecter les arguments de test

# Charge les variables d'environnement depuis .env
load_dotenv()
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'vt_analyzer.middleware.DisableCSRFMiddleware',  # Add this line BEFORE CsrfViewMiddleware
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'allauth.account.middleware.AccountMiddleware',
]
# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = os.getenv('SECRET_KEY')
DEBUG = os.getenv('DEBUG', 'False') == 'True'

ALLOWED_HOSTS = ['127.0.0.1', 'localhost']
# S'il est déployé, ajoutez votre domaine
# ALLOWED_HOSTS.append(os.getenv('DEPLOYED_HOST'))

# Définition des applications
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',

    # Apps tierces pour l'API
    'rest_framework',
    'rest_framework.authtoken',
    'rest_framework_simplejwt',
    'dj_rest_auth',
    'django.contrib.sites', # Requis par dj-rest-auth
    'allauth', # Requis par dj-rest-auth
    'allauth.account', # Requis par dj-rest-auth
    'dj_rest_auth.registration', # Requis par dj-rest-auth
    'corsheaders', # Pour autoriser les requêtes Angular

    # Vos applications
    'vt_analyzer',
]

# SITE_ID requis pour 'django.contrib.sites'
SITE_ID = 1 

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    # CORS Middleware (DOIT être placé haut)
    "corsheaders.middleware.CorsMiddleware",
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    # Middleware Allauth
    "allauth.account.middleware.AccountMiddleware",
]

ROOT_URLCONF = 'virus_analyzer.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'virus_analyzer.wsgi.application'

# ===================================================================
# CONFIGURATION BASE DE DONNÉES OPTIMISÉE POUR LES TESTS
# ===================================================================

# Détecter si nous sommes en mode test ou Locust
TEST_MODE = 'test' in sys.argv or 'locust' in sys.argv

if TEST_MODE:
    # Configuration optimisée pour les tests de performance
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': ':memory:',  # Base en mémoire pour plus de vitesse
            'OPTIONS': {
                'timeout': 20,
            }
        }
    }
    
    # Accélérer les tests d'authentification
    PASSWORD_HASHERS = [
        'django.contrib.auth.hashers.MD5PasswordHasher',
    ]
    
    # Désactiver le debug pour les tests
    DEBUG = False
    
    # Désactiver certains middlewares pour les tests
    if 'locust' in sys.argv:
        # Filtrer les middlewares lourds pendant les tests Locust
        MIDDLEWARE = [
            m for m in MIDDLEWARE 
            if 'DebugToolbarMiddleware' not in str(m)
        ]
        
        # Logging spécifique pour Locust
        LOGGING = {
            'version': 1,
            'disable_existing_loggers': False,
            'handlers': {
                'locust_file': {
                    'level': 'INFO',
                    'class': 'logging.FileHandler',
                    'filename': BASE_DIR / 'logs' / 'locust.log',
                },
            },
            'loggers': {
                'django': {
                    'handlers': ['locust_file'],
                    'level': 'WARNING',
                    'propagate': True,
                },
                'vt_analyzer': {
                    'handlers': ['locust_file'],
                    'level': 'INFO',
                    'propagate': True,
                },
            },
        }
else:
    # Configuration normale de production/développement
    DATABASES = {
        'default': dj_database_url.config(default=f"sqlite:///{BASE_DIR / 'db.sqlite3'}")
    }

# Modèle d'utilisateur personnalisé
AUTH_USER_MODEL = 'vt_analyzer.User'

# Validation de mot de passe
AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',},
]

# Internationalisation
LANGUAGE_CODE = 'fr-fr'
TIME_ZONE = 'Europe/Paris'
USE_I18N = True
USE_TZ = True

# Fichiers statiques et médias
STATIC_URL = 'static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'
MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
CSRF_EXEMPT_URLS = [
    r'^api/',
]
# ===================================================================
# CONFIGURATION DE L'API REST (DRF, JWT, CORS)
# ===================================================================
CSRF_COOKIE_SECURE = False
CSRF_COOKIE_HTTPONLY = False
SESSION_COOKIE_SECURE = False
# Configuration CORS (Qui peut appeler votre API)
CORS_ALLOWED_ORIGINS = os.getenv('CORS_ALLOWED_ORIGINS', 'http://localhost:4200').split(',')
CORS_ALLOW_CREDENTIALS = True # Autorise les cookies (pour l'authentification)

# Configuration Django Rest Framework
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_simplejwt.authentication.JWTAuthentication',
        'rest_framework.authentication.SessionAuthentication',
    ),
    'DEFAULT_PERMISSION_CLASSES': (
        'rest_framework.permissions.IsAuthenticated',
    ),
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    'PAGE_SIZE': 20,
    
    # Optimisations pour les tests
    'DEFAULT_THROTTLE_CLASSES': [
        'rest_framework.throttling.AnonRateThrottle',
        'rest_framework.throttling.UserRateThrottle'
    ],
    'DEFAULT_THROTTLE_RATES': {
        'anon': '1000/day',
        'user': '5000/day'
    }
}
CSRF_TRUSTED_ORIGINS = ['http://127.0.0.1:8000', 'http://localhost:8000']

# Configuration Simple JWT (Tokens)
SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=60),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=7),
    
    # Optimisations pour les tests
    "ALGORITHM": "HS256",
    "SIGNING_KEY": SECRET_KEY,
}

# Configuration dj-rest-auth
REST_AUTH = {
    'USE_JWT': True,
    'JWT_AUTH_HTTPONLY': False,
    'USER_DETAILS_SERIALIZER': 'vt_analyzer.serializers.UserDetailsSerializer',
    'LOGIN_SERIALIZER': 'dj_rest_auth.serializers.LoginSerializer',
    'SESSION_LOGIN': False,  # Add this line to disable session login
}


# Configuration Allauth (nécessaire pour dj-rest-auth)
ACCOUNT_USER_MODEL_USERNAME_FIELD = 'username' # Utilise 'username'
ACCOUNT_EMAIL_REQUIRED = True
ACCOUNT_USERNAME_REQUIRED = True # 'username' est requis
ACCOUNT_AUTHENTICATION_METHOD = 'username_email' # S'authentifier avec l'un ou l'autre
ACCOUNT_EMAIL_VERIFICATION = 'none' # Mettez 'mandatory' en production
EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend' # Pour le dev

# ===================================================================
# VOS CLÉS API (Chargées depuis .env)
# ===================================================================
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
OTX_API_KEY = os.getenv('OTX_API_KEY')
IPINFO_TOKEN = os.getenv('IPINFO_TOKEN')

# ===================================================================
# CONFIGURATIONS SPÉCIFIQUES POUR LOCUST ET TESTS DE PERFORMANCE
# ===================================================================

# Créer le dossier logs si nécessaire
if not os.path.exists(BASE_DIR / 'logs'):
    os.makedirs(BASE_DIR / 'logs')

# Variables d'environnement pour les tests
LOCUST_TEST_USER_COUNT = int(os.getenv('LOCUST_TEST_USER_COUNT', '100'))
LOCUST_TEST_SPAWN_RATE = int(os.getenv('LOCUST_TEST_SPAWN_RATE', '10'))

# Configuration du cache pour les tests
if TEST_MODE:
    CACHES = {
        'default': {
            'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
            'LOCATION': 'unique-snowflake',
        }
    }
    
    # Désactiver certaines vérifications
    SECURE_SSL_REDIRECT = False
    SECURE_HSTS_SECONDS = 0
    SECURE_HSTS_INCLUDE_SUBDOMAINS = False
    SECURE_HSTS_PRELOAD = False
    
    # Optimiser les sessions
    SESSION_ENGINE = 'django.contrib.sessions.backends.cache'
    SESSION_CACHE_ALIAS = 'default'
else:
    # Configuration cache normale
    CACHES = {
        'default': {
            'BACKEND': 'django.core.cache.backends.redis.RedisCache',
            'LOCATION': os.getenv('REDIS_URL', 'redis://127.0.0.1:6379/1'),
        }
    }

# Configuration pour gérer les fichiers uploadés pendant les tests
if TEST_MODE:
    # Stocker les fichiers en mémoire pendant les tests
    DEFAULT_FILE_STORAGE = 'django.core.files.storage.FileSystemStorage'
    
    # Désactiver la génération de PDF pendant les tests
    PDF_GENERATION_ENABLED = False
else:
    # Configuration normale du stockage
    DEFAULT_FILE_STORAGE = 'django.core.files.storage.FileSystemStorage'

# Middleware personnalisé pour désactiver CSRF pendant les tests
if TEST_MODE:
    # Ajouter le middleware de désactivation CSRF si nécessaire
    MIDDLEWARE.insert(0, 'vt_analyzer.middleware.DisableCSRFMiddleware')