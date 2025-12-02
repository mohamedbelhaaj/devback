#!/bin/bash
# setup_test_users.sh

echo "🔧 Configuration des utilisateurs de test..."

# Vérifier si Django est installé
if ! python -c "import django" &> /dev/null; then
    echo "❌ Django n'est pas installé"
    exit 1
fi

# Créer le fichier Python
cat > /tmp/create_users.py << 'EOF'
import os
import django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'virus_analyzer.settings')
django.setup()

from django.contrib.auth import get_user_model
User = get_user_model()

# Créer les utilisateurs
users = [
    ('test_analyst', 'test123', 'analyst'),
    ('test_admin', 'admin123', 'admin'),
]

for username, password, role in users:
    user, created = User.objects.get_or_create(
        username=username,
        defaults={'email': f'{username}@test.com', 'role': role, 'is_active': True}
    )
    user.set_password(password)
    user.save()
    if created:
        print(f'✅ {username} créé')
    else:
        print(f'↻ {username} mis à jour')

print(f'\n🎯 {len(users)} utilisateurs configurés')
EOF

# Exécuter le script
python /tmp/create_users.py

# Nettoyer
rm /tmp/create_users.py

echo "✅ Configuration terminée!"