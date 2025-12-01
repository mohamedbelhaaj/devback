import pytest
import os
import sys
from pathlib import Path
print("🔍 Recherche du chemin du projet...")

from pathlib import Path
def test_credentials():
    """Identifiants de test mock"""
    return {
        "admin": {"username": "admin", "password": "admin123"},
        "analyst": {"username": "analyst", "password": "analyst123"}
    }

@pytest.hookimpl(tryfirst=True)
def pytest_runtest_setup(item):
    """Désactiver Django pour les tests marqués 'ui'"""
    if "ui" in item.keywords:
        # Supprimer la variable d'environnement Django
        os.environ.pop("DJANGO_SETTINGS_MODULE", None)

# Option: Créer une fixture avec un nom différent
@pytest.fixture
def app_url():
    """URL de l'application (nom différent pour éviter le conflit)"""
    return "http://localhost:8000"