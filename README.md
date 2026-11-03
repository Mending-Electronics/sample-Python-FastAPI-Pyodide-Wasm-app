# VBA Audit local

Application de bureau autonome orientée **inspection défensive** de fichiers Excel et de code VBA.
L’interface Vue et le moteur Python s’exécutent dans le navigateur; les rapports sont conservés dans
SQLite en mémoire puis sauvegardés dans IndexedDB sur le poste.

## Démarrage

- Linux x86_64 : `./start.sh`, puis ouvrir l’URL affichée.
- Windows : exécuter `.\start.ps1` dans Windows PowerShell, puis ouvrir l’URL affichée.

Le serveur Linux est un binaire Rust précompilé, sans runtime Python ou Rust requis pour le démarrage.
Sur Windows, le serveur statique utilise `HttpListener` fourni par Windows PowerShell/.NET. Les deux
serveurs écoutent uniquement sur `127.0.0.1`; ils ne servent que `web/` et `backend/`.

Pyodide 314.0.7, Bootstrap 5.3.8, Vue 3.5.44, Bootstrap Icons 1.13.1 et Swagger UI 5.34.1
sont vendoriés dans `web/vendor/`. Aucun accès Internet ni runtime Python système n’est requis au
démarrage. Le cache HTTP du serveur est désactivé afin de faciliter le rechargement des fichiers WASM.
La politique CSP autorise l’évaluation de templates statiques nécessaire au build global de Vue; les
sources chargées par l’utilisateur ne sont jamais interprétées comme du HTML ou du JavaScript.
Les licences et notices des dépendances vendoriées sont conservées dans `web/vendor/licenses/`.

## Capacités et limites de sécurité

- Analyse statique de modules `.bas`, `.cls`, `.frm`, `.vba` ou `.txt`.
- Remplacement dans l’aperçu des appels littéraux `Chr`/`ChrW`; aucun code n’est évalué ou exécuté.
- Heuristiques d’indicateurs VBA et comportement de type Dridex; il ne s’agit pas d’un verdict antivirus.
- Lecture des marqueurs de protection des feuilles et de la structure dans `.xlsx`/`.xlsm`.
- Rapports SQLite stockés localement. Le code source analysé n’est pas inclus dans les rapports persistés.
- Aucun déverrouillage, suppression ou contournement de protection Excel/VBA. Les projets VBA binaires
  ne sont ni extraits ni analysés; exporter les modules depuis Excel pour lancer une analyse source.

## API et documentation

La route `/docs` affiche le contrat OpenAPI disponible aussi sur `/openapi.json`. Les fonctions métier
Python sont appelées directement par Vue via Pyodide. Un navigateur exécutant du WASM ne peut pas ouvrir
un socket serveur : ce contrat n’est donc pas un serveur FastAPI HTTP et Swagger ne peut pas invoquer
des routes réseau. Cette contrainte évite d’embarquer un interpréteur Python système sur le poste client.

Modules métier : `backend/vba_audit/`. Tests : `python3 -m unittest discover -s tests`.

Pour reconstruire le serveur Linux sur la machine cible :

```sh
rustc --edition=2021 -C opt-level=s -C strip=symbols \
  tools/local_server.rs -o bin/linux-x86_64/local-audit-server
```
