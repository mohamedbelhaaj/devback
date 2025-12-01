import os
from pathlib import Path

print("📁 Structure du projet:")
current = Path.cwd()
for item in current.rglob("*"):
    if item.is_dir():
        # Afficher les dossiers importants
        if item.name in ['venv', '.git', '__pycache__', '.pytest_cache']:
            continue
        rel_path = item.relative_to(current)
        print(f"📁 {rel_path}")
        # Afficher les fichiers .py dans ce dossier
        py_files = list(item.glob("*.py"))
        if py_files:
            for py_file in py_files[:5]:  # 5 premiers
                print(f"   📄 {py_file.name}")
            if len(py_files) > 5:
                print(f"   ... et {len(py_files)-5} autres")
    elif item.suffix == '.py' and item.parent == current:
        print(f"📄 {item.name}")

print("\n🔍 Recherche spécifique de manage.py et settings.py:")
for item in current.rglob("manage.py"):
    print(f"✅ manage.py trouvé à: {item.relative_to(current)}")

for item in current.rglob("settings.py"):
    print(f"✅ settings.py trouvé à: {item.relative_to(current)}")