# Inventaire NAT Meraki

Application web locale qui parcourt les organisations Meraki accessibles à la clé API, repère les réseaux avec un appareil MX et affiche les règles de redirection de ports, NAT 1:1 et NAT 1:Many. Pendant le scan, la page indique l'organisation en cours et l'avancement. Elle affiche également les adresses WAN1 et WAN2 des MX, ainsi que l'IP publique détectée si Meraki la fournit. Pour chaque IP LAN de destination, elle cherche le client Meraki correspondant et affiche l'OS rapporté par Meraki, s'il est disponible.

Les règles NAT sont configurées au niveau du réseau Meraki. L'application affiche donc une fiche par réseau MX et les appareils MX présents dans ce réseau.

## Démarrage

Python 3.10 ou plus récent est recommandé.

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
py app.py
```

Copiez `.env.example` vers `.env`, puis remplacez `remplacer_par_votre_cle_api` par une clé API Dashboard active créée depuis le profil de votre utilisateur Meraki (Dashboard > profil > API access). Gardez la valeur brute, sans `Bearer`.

Puis ouvrir <http://127.0.0.1:8086>.

Le fichier `.env` est chargé au démarrage et ses valeurs remplacent celles déjà présentes dans l'environnement du processus. Pour changer le port, modifiez `PORT` dans `.env` (8086 par défaut), puis redémarrez l'application.

La clé doit avoir les droits de lecture sur les organisations, réseaux, appareils, clients et paramètres d'appliance/firewall. Elle est lue depuis l'environnement, n'est pas demandée dans la page web et n'est pas enregistrée par l'application.

Les informations clients sont recherchées sur les 30 derniers jours. La classification de l'OS est celle fournie par Meraki et peut être absente ou ne plus refléter l'état actuel du Site. Les organisations et réseaux non autorisés par la clé ne peuvent pas être inventoriés.
