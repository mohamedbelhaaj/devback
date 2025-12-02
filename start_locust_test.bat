@echo off
echo ============================================================
echo   SCRIPT DE LANCEMENT AUTOMATIQUE LOCUST
echo ============================================================
echo.

REM Vérifier si Django tourne déjà
echo [1/4] Verification du serveur Django...
curl -s http://127.0.0.1:8000/ >nul 2>&1
if %errorlevel% == 0 (
    echo [OK] Django est deja en cours d'execution
    goto :check_users
) else (
    echo [INFO] Django n'est pas lance
    echo [ACTION] Lancement de Django dans une nouvelle fenetre...
    start "Django Server" cmd /k "python manage.py runserver"
    echo [ATTENTE] 5 secondes pour le demarrage...
    timeout /t 5 /nobreak >nul
)

:check_users
echo.
echo [2/4] Creation des utilisateurs de test...
python create_test_users.py
if %errorlevel% neq 0 (
    echo [ERREUR] Impossible de creer les utilisateurs
    echo [INFO] Assurez-vous que la base de donnees est migree
    pause
    exit /b 1
)

echo.
echo [3/4] Verification pre-tests...
python pre_locust_check.py
if %errorlevel% neq 0 (
    echo.
    echo [ERREUR] Les pre-tests ont echoue
    echo [INFO] Corrigez les problemes avant de continuer
    pause
    exit /b 1
)

echo.
echo [4/4] Lancement de Locust...
echo [INFO] Interface web: http://localhost:8089
echo.
locust -f locustfile.py --host=http://127.0.0.1:8000

pause