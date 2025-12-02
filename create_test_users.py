"""
Script pour créer les utilisateurs de test pour Locust
Usage: python manage.py shell < create_test_users.py
Ou: python create_test_users.py
"""

import os
import django

# Configuration Django si exécuté directement
if __name__ == "__main__":
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'virus_analyzer.settings')
    django.setup()

from django.contrib.auth import get_user_model
from django.db import IntegrityError

User = get_user_model()

def create_test_users():
    """Crée les utilisateurs nécessaires pour les tests Locust"""
    
    users_to_create = [
        {
            'username': 'test_analyst',
            'email': 'analyst@test.com',
            'password': 'test123',
            'is_staff': False,
            'is_superuser': False,
        },
        {
            'username': 'test_admin',
            'email': 'admin@test.com',
            'password': 'admin123',
            'is_staff': True,
            'is_superuser': True,
        }
    ]
    
    print("=" * 60)
    print("🔧 CRÉATION DES UTILISATEURS DE TEST")
    print("=" * 60)
    
    for user_data in users_to_create:
        username = user_data['username']
        
        try:
            # Vérifier si l'utilisateur existe déjà
            if User.objects.filter(username=username).exists():
                print(f"⚠️  L'utilisateur '{username}' existe déjà, suppression...")
                User.objects.filter(username=username).delete()
            
            # Créer l'utilisateur
            user = User.objects.create_user(
                username=user_data['username'],
                email=user_data['email'],
                password=user_data['password']
            )
            
            # Définir les permissions
            user.is_staff = user_data['is_staff']
            user.is_superuser = user_data['is_superuser']
            user.save()
            
            print(f"✅ Utilisateur '{username}' créé avec succès")
            print(f"   - Email: {user_data['email']}")
            print(f"   - Staff: {user_data['is_staff']}")
            print(f"   - Superuser: {user_data['is_superuser']}")
            print()
            
        except IntegrityError as e:
            print(f"❌ Erreur lors de la création de '{username}': {e}")
        except Exception as e:
            print(f"❌ Erreur inattendue pour '{username}': {e}")
    
    print("=" * 60)
    print("📊 RÉCAPITULATIF")
    print("=" * 60)
    print(f"Total d'utilisateurs dans la base: {User.objects.count()}")
    print(f"Analystes: {User.objects.filter(is_staff=False).count()}")
    print(f"Admins: {User.objects.filter(is_staff=True).count()}")
    print("=" * 60)

if __name__ == "__main__":
    create_test_users()