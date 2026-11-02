# Inventaire NAT Meraki

Application web locale qui parcourt les organisations Meraki accessibles à la clé API, repère les réseaux avec un appareil MX et affiche les règles de redirection de ports, NAT 1:1 et NAT 1:Many. Pendant le scan, la page indique l'organisation en cours et l'avancement. Elle affiche également les adresses WAN1 et WAN2 des MX, ainsi que l'IP publique détectée si Meraki la fournit. Pour chaque IP LAN de destination, elle cherche le client Meraki correspondant et affiche l'OS rapporté par Meraki, s'il est disponible.

Les règles NAT sont configurées au niveau du réseau Meraki. L'application affiche donc une fiche par réseau MX et les appareils MX présents dans ce réseau.

## Démarrage

Python 3.10 ou plus récent est recommandé.

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:MERAKI_DASHBOARD_API_KEY = "COLLEZ_ICI_VOTRE_CLE_API_MERAKI"
py app.py
```

Remplacez `COLLEZ_ICI_VOTRE_CLE_API_MERAKI` par une clé API Dashboard active créée depuis le profil de votre utilisateur Meraki (Dashboard > profil > API access). Gardez les guillemets, mais ne mettez pas `Bearer` devant la clé. Cette variable vaut uniquement pour la fenêtre PowerShell courante : définissez-la avant `py app.py` et redémarrez l’application si vous changez la clé.

Puis ouvrir <http://127.0.0.1:5000>.

Vous pouvez aussi copier `.env.example` vers `.env` et y définir `MERAKI_DASHBOARD_API_KEY`. Le fichier `.env` est chargé au démarrage.

La clé doit avoir les droits de lecture sur les organisations, réseaux, appareils, clients et paramètres d'appliance/firewall. Elle est lue depuis l'environnement, n'est pas demandée dans la page web et n'est pas enregistrée par l'application.

Les informations clients sont recherchées sur les 30 derniers jours. La classification de l'OS est celle fournie par Meraki et peut être absente ou ne plus refléter l'état actuel du terminal. Les organisations et réseaux non autorisés par la clé ne peuvent pas être inventoriés.
