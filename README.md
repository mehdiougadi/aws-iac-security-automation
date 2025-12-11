# AWS IaC Security Automation

Ce projet automatise le déploiement d'une infrastructure AWS sécurisée (EC2, S3, CloudWatch, CloudTrail) et inclut une analyse de sécurité via Trivy.

## Structure du Projet

- **`main.py`** : Script principal qui déploie l'architecture complète sur AWS.
- **`cleanup.py`** : Script de nettoyage pour supprimer toutes les ressources créées.
- **`lab4-template-template-*.yaml`** : Template CloudFormation généré à partir de l'infrastructure déployée (utilisé pour l'analyse Trivy).
- **`results.json`** : Résultats bruts complets du scan de vulnérabilité Trivy.
- **`cve.json`** : Extrait des vulnérabilités de sévérité "HIGH" et "CRITICAL" trouvées.
- **`requirements.txt`** : Liste des dépendances Python nécessaires.

## Prérequis

- Python 3.x installé.
- Un compte AWS avec les permissions nécessaires (ou un environnement Learner Lab).
- (Optionnel) Fichier `~/.aws/credentials` configuré. Si absent, le script demandera les identifiants.

## Installation

Installez les dépendances nécessaires :

```bash
pip install -r requirements.txt
```

## Utilisation

### 1. Déploiement de l'infrastructure

Lancez le script principal pour créer les ressources (EC2, S3, CloudWatch, CloudTrail) :

```bash
python main.py
```
*Le script vérifiera vos identifiants AWS avant de commencer.*

### 2. Analyse de Sécurité

L'analyse de sécurité a été effectuée en deux étapes :
1. Génération d'un template CloudFormation (`.yaml`) depuis l'infrastructure déployée (via AWS IaC Generator).
2. Scan de ce template avec Trivy.

Les résultats sont disponibles dans :
- `results.json` (Scan complet)
- `cve.json` (Vulnérabilités critiques/hautes uniquement)

### 3. Nettoyage

Pour supprimer toutes les ressources créées et éviter des coûts supplémentaires :

```bash
python cleanup.py
```
