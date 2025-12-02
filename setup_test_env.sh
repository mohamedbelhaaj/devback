#!/bin/bash
# run_final_test.sh - Script final pour lancer les tests

echo "🚀 DERNIÈRE ÉTAPE : Lancement des tests de performance"
echo "======================================================"

# Vérifier que Django tourne
echo "🔍 Vérification du serveur Django..."
if curl -s http://localhost:8000 > /dev/null; then
    echo "✅ Django est en cours d'exécution sur http://localhost:8000"
else
    echo "❌ Django n'est pas accessible sur http://localhost:8000"
    echo "Lancez d'abord : python manage.py runserver"
    exit 1
fi

# Demander les paramètres
read -p "👥 Nombre d'utilisateurs [10] : " users
users=${users:-10}

read -p "📈 Spawn rate (utilisateurs/seconde) [2] : " spawn_rate
spawn_rate=${spawn_rate:-2}

read -p "⏱️  Durée du test (ex: 30s, 1m, 5m) [1m] : " run_time
run_time=${run_time:-1m}

echo ""
echo "🎯 Configuration du test :"
echo "   Utilisateurs: $users"
echo "   Spawn rate: $spawn_rate/sec"
echo "   Durée: $run_time"
echo "   Host: http://localhost:8000"
echo ""

# Options
echo "📋 Choisissez le mode :"
echo "   1. Interface web (http://localhost:8089)"
echo "   2. Mode headless (sans interface)"
echo "   3. Les deux (interface + CSV)"
read -p "Votre choix [1] : " mode
mode=${mode:-1}

case $mode in
    1)
        # Mode interface web uniquement
        echo "🌐 Lancement de l'interface web sur http://localhost:8089"
        echo "📌 Ouvrez http://localhost:8089 dans votre navigateur"
        locust -f locustfile.py --host=http://localhost:8000
        ;;
    2)
        # Mode headless uniquement
        echo "🧪 Lancement en mode headless..."
        locust -f locustfile.py \
            --host=http://localhost:8000 \
            --users=$users \
            --spawn-rate=$spawn_rate \
            --run-time=$run_time \
            --headless
        ;;
    3)
        # Mode complet avec interface web et export CSV
        timestamp=$(date +"%Y%m%d_%H%M%S")
        echo "📊 Lancement complet avec export CSV..."
        
        # Lancer en arrière-plan avec CSV export
        locust -f locustfile.py \
            --host=http://localhost:8000 \
            --users=$users \
            --spawn-rate=$spawn_rate \
            --run-time=$run_time \
            --headless \
            --csv=results/locust/test_${timestamp} \
            --html=results/locust/report_${timestamp}.html &
        
        LOCUST_PID=$!
        
        echo "📈 Test en cours... (PID: $LOCUST_PID)"
        echo "📁 Résultats dans: results/locust/test_${timestamp}*.csv"
        echo "🌐 Interface web: http://localhost:8089"
        
        # Attendre la fin du test
        wait $LOCUST_PID
        
        echo "✅ Test terminé!"
        echo "📊 Résultats disponibles dans results/locust/"
        ;;
    *)
        echo "❌ Choix invalide"
        ;;
esac