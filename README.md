# Utilisation de l'intelligence artificielle pour la détection d'attaques par déni de service
Le but de ce projet est de développer une intelligence artificielle pour classifier d'éventuelles attaques DDoS dans un réseau.

## Fonctionnalités du projet
- Sniffer des paquets : Capture les paquets à partir d'une interface choisie et affiche les informations des paquets.
- Collection de données : Rassemble les données à partir de la capture de paquets et les écrit dans un fichier CSV.
- Entraînement du réseau neuronal : Entraîne un MLP en utilisant les données collectées dans le fichier CSV.
- Réseau neuronal en live : Utilise un MLP entraîné pour détecter les attaques DDoS en temps réel.

## Requirements

Pour exécuter ce projet, il vous faut les bibliothèques suivantes:

- pandas
- scikit-learn
- matplotlib
- numpy
- pyshark
- netifaces

Vous pouvez les installer avec:

```bash
pip install -r requirements.txt

