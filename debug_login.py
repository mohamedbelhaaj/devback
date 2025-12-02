"""
Script de débogage détaillé pour identifier le problème de login
"""

import requests
import json

BASE_URL = "http://localhost:8000"

print("=" * 70)
print("🔍 DÉBOGAGE DÉTAILLÉ DU LOGIN")
print("=" * 70)

# Test 1: Vérifier la structure de l'endpoint
print("\n📋 TEST 1: Structure de l'endpoint")
print("-" * 70)

payload = {
    "username": "test_analyst",
    "password": "test123"
}

try:
    response = requests.post(
        f"{BASE_URL}/api/auth/login/",
        json=payload,
        headers={"Content-Type": "application/json"},
        timeout=10
    )
    
    print(f"Status Code: {response.status_code}")
    print(f"\nResponse Headers:")
    for key, value in response.headers.items():
        print(f"  {key}: {value}")
    
    print(f"\n📄 Response Body:")
    print("-" * 70)
    try:
        # Essayer de parser en JSON
        data = response.json()
        print(json.dumps(data, indent=2, ensure_ascii=False))
    except:
        # Si ce n'est pas du JSON, afficher le texte brut
        print(response.text[:1000])  # Premiers 1000 caractères
    
    print("\n" + "=" * 70)
    
    # Analyse détaillée selon le status code
    if response.status_code == 500:
        print("❌ ERREUR 500 - Internal Server Error")
        print("\n🔧 CAUSES POSSIBLES:")
        print("  1. Les utilisateurs n'existent pas dans la base de données")
        print("  2. Erreur dans la vue Django (views.py)")
        print("  3. Problème de configuration JWT")
        print("  4. Erreur dans le serializer")
        print("\n📋 ACTIONS À FAIRE:")
        print("  1. Vérifiez les logs Django (terminal où runserver tourne)")
        print("  2. Créez les utilisateurs avec le script fourni")
        print("  3. Vérifiez votre views.py ligne par ligne")
        
    elif response.status_code == 401:
        print("❌ ERREUR 401 - Unauthorized")
        print("\n🔧 CAUSES POSSIBLES:")
        print("  1. Username ou password incorrect")
        print("  2. L'utilisateur existe mais le password est différent")
        print("\n📋 ACTIONS À FAIRE:")
        print("  1. Vérifiez que l'utilisateur existe:")
        print("     python manage.py shell")
        print("     >>> from django.contrib.auth import get_user_model")
        print("     >>> User = get_user_model()")
        print("     >>> User.objects.filter(username='test_analyst').exists()")
        
    elif response.status_code == 400:
        print("❌ ERREUR 400 - Bad Request")
        print("\n🔧 CAUSES POSSIBLES:")
        print("  1. Format de données incorrect")
        print("  2. Champs manquants")
        print("  3. Validation échouée")
        
    elif response.status_code == 404:
        print("❌ ERREUR 404 - Not Found")
        print("\n🔧 CAUSES POSSIBLES:")
        print("  1. L'URL est incorrecte")
        print("  2. Les routes ne sont pas configurées dans urls.py")
        
    elif response.status_code == 200:
        print("✅ LOGIN RÉUSSI!")
        try:
            data = response.json()
            if 'access' in data:
                print(f"\n🎫 Token JWT reçu: {data['access'][:50]}...")
            else:
                print("⚠️  Pas de token 'access' dans la réponse")
        except:
            pass
    
    print("\n" + "=" * 70)
    
except requests.exceptions.ConnectionError:
    print("❌ Impossible de se connecter au serveur")
    print("✋ Assurez-vous que Django est lancé:")
    print("   python manage.py runserver")
    
except Exception as e:
    print(f"❌ Exception: {e}")

# Test 2: Tester différentes variations
print("\n\n📋 TEST 2: Variations de payload")
print("=" * 70)

test_cases = [
    {
        "name": "Avec username et password",
        "payload": {"username": "test_analyst", "password": "test123"}
    },
    {
        "name": "Avec email et password",
        "payload": {"email": "analyst@test.com", "password": "test123"}
    },
    {
        "name": "Payload vide",
        "payload": {}
    },
    {
        "name": "Admin credentials",
        "payload": {"username": "test_admin", "password": "admin123"}
    }
]

for test_case in test_cases:
    print(f"\n🧪 Test: {test_case['name']}")
    print("-" * 70)
    
    try:
        response = requests.post(
            f"{BASE_URL}/api/auth/login/",
            json=test_case['payload'],
            headers={"Content-Type": "application/json"},
            timeout=5
        )
        
        print(f"Status: {response.status_code}", end="")
        
        if response.status_code == 200:
            print(" ✅")
        elif response.status_code == 500:
            print(" ❌ (Erreur serveur)")
        elif response.status_code == 401:
            print(" ❌ (Non autorisé)")
        elif response.status_code == 400:
            print(" ❌ (Mauvaise requête)")
        else:
            print(f" ⚠️  (Inattendu)")
        
        # Afficher un aperçu de la réponse
        try:
            data = response.json()
            if len(str(data)) < 200:
                print(f"Response: {data}")
        except:
            if len(response.text) < 200:
                print(f"Response: {response.text}")
                
    except Exception as e:
        print(f"❌ Erreur: {e}")

# Test 3: Informations système
print("\n\n📋 TEST 3: Informations système")
print("=" * 70)

try:
    # Essayer de récupérer des infos sur l'API
    response = requests.options(f"{BASE_URL}/api/auth/login/", timeout=5)
    print(f"OPTIONS request status: {response.status_code}")
    
    if 'Allow' in response.headers:
        print(f"Méthodes autorisées: {response.headers['Allow']}")
    
except:
    pass

print("\n" + "=" * 70)
print("🎯 PROCHAINES ÉTAPES:")
print("=" * 70)
print("""
1. REGARDEZ LES LOGS DJANGO maintenant
   Dans le terminal où 'python manage.py runserver' tourne,
   vous devriez voir l'erreur exacte qui cause le 500.

2. CRÉEZ LES UTILISATEURS si ce n'est pas fait:
   
   python manage.py shell
   
   Puis dans le shell:
   
   from django.contrib.auth import get_user_model
   User = get_user_model()
   
   # Créer l'analyste
   User.objects.create_user(
       username='test_analyst',
       email='analyst@test.com', 
       password='test123'
   )
   
   # Créer l'admin
   User.objects.create_superuser(
       username='test_admin',
       email='admin@test.com',
       password='admin123'
   )

3. VÉRIFIEZ votre views.py:
   L'endpoint /api/auth/login/ doit être correctement implémenté

4. COPIEZ-COLLEZ l'erreur des logs Django ici pour plus d'aide
""")