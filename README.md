# Utilisation de l'intelligence artificielle pour la détection d'attaques par déni de service
Le but de ce projet est de développer une intelligence artificielle pour classifier d'éventuelles attaques DDoS dans un réseau.

!Meriam & Yazid - complétez ci-dessous ce qui manque côté réseau!

## Fonctionnalités du projet
- Sniffer des paquets : Capture les paquets à partir d'une interface choisie et affiche les informations des paquets.
- Collection de données : Rassemble les données à partir de la capture de paquets et les écrit dans un fichier CSV.
- Entraînement du réseau neuronal : Entraîne un MLP en utilisant les données collectées dans le fichier CSV.
- Vérification des données : Permet de visualiser les données à l'intérieur d'un fichier CSV.
- Réseau neuronal en live : Utilise un MLP entraîné pour détecter les attaques DDoS en temps réel.

# TODO

1. **Sniffer de paquets** :
    - Utilisez `snappi` en Python pour capturer et analyser les paquets réseau.
    - Extrayez les informations pertinentes de chaque paquet telles que l'IP source/destination, les ports, la longueur du paquet, etc.
    - Permettez à l'utilisateur de choisir une interface réseau pour la capture des paquets (ou pas?)

2. **Collecteur de données pour le réseau neuronal artificiel (ANN)** :
    - Créez une fonction pour capturer continuellement des paquets et stocker leurs informations dans un fichier CSV.
    - Incluez des caractéristiques telles que la couche la plus élevée, la couche de transport, l'IP source/destination, les ports, la longueur du paquet, etc.
    - Attribuez des étiquettes à chaque paquet indiquant s'il est bénin ou malveillant (à des fins d'entraînement).

3. **Entraîneur du réseau neuronal** :
    - Implémentez un réseau neuronal artificiel (ANN) à l'aide de `scikit-learn` ou `TensorFlow`.
    - Chargez l'ensemble de données créé à l'étape précédente et divisez-le en ensembles d'entraînement et de test.
    - Entraînez l'ANN en utilisant les données d'entraînement et évaluez ses performances sur les données de test.
    - Enregistrez le modèle entraîné pour une utilisation future.

4. **Visionneur de données** (optionnel) :
    - Créez une fonction pour afficher les données à l'intérieur du fichier CSV de l'ensemble de données.
    - Permettez aux utilisateurs de voir toutes les données, uniquement les données numériques ou uniquement les données catégoriques.

5. **Réseau neuronal en temps réel** :
    - Implémentez la détection en temps réel des attaques par DDoS en utilisant le modèle ANN entraîné.
    - Capturez continuellement des paquets et envoyez-les dans l'ANN pour la classification.
    - Prenez des mesures appropriées lors de la détection d'une attaque DDoS, telles que la journalisation de l'événement ou l'alerte de l'utilisateur (optionnel)

6. **ANN visuel** (optionnel) (si on a le temps) :
    - Créez une représentation visuelle du modèle ANN.
    - Visualisez la couche d'entrée, les couches cachées et la couche de sortie ainsi que leurs connexions et activations neuronales.

