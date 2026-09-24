# A4 — Design technique

## Principe

`cli.py` est le seul fichier modifié. Tous les modules existants sont
appelés tels quels — aucune modification de leur logique ou signature.

---

## 1. `netlab scan` — pipeline complet

### Flux

```python
@app.command()
def scan(target, profile, session):
    # 1. Créer la session
    session_id = session or f"session-{uuid.uuid4().hex[:8]}"
    init_db(session_id)
    save_session(session_id, target=target, profile=profile)

    # 2. Confirmation globale AVANT tout trafic réseau
    confirmed = typer.confirm(f"Start full scan on {target}?")
    if not confirmed: ...

    # 3. DISCOVER — device_fingerprint
    from recon.device_fingerprint import fingerprint
    host_findings = fingerprint(target, session_id)
    save_findings(host_findings)
    # Extraire les IPs actives des Findings pour les étapes suivantes
    active_ips = {f.target_ip for f in host_findings if f.target_ip}

    # 4. DETECT — tcp_scan sur chaque hôte actif
    from detect.tcp_scan import tcp_scan
    all_port_findings = []
    for ip in active_ips:
        port_findings = tcp_scan(ip, session_id, profile=profile)
        all_port_findings.extend(port_findings)
    save_findings(all_port_findings)

    # 5. DETECT — udp_scan sur chaque hôte (optionnel selon profil)
    from detect.udp_scan import udp_scan
    all_udp_findings = []
    for ip in active_ips:
        udp_findings = udp_scan(ip, session_id, profile=profile)
        all_udp_findings.extend(udp_findings)
    save_findings(all_udp_findings)

    # 6. DETECT — service_detection (CVE enrichment)
    from detect.service_detection import enrich_findings
    all_scan_findings = all_port_findings + all_udp_findings
    enriched = enrich_findings(all_scan_findings)

    # 7. DETECT — misconfig_detection (par hôte)
    from detect.misconfig_detection import detect_misconfigs
    misconfig_findings = []
    for ip in active_ips:
        ip_findings = [f for f in enriched if f.target_ip == ip]
        misconfig_findings.extend(detect_misconfigs(ip_findings, session_id))

    # 8. EXPLAIN — enrichir avec knowledge_base
    from knowledge.knowledge_base import get_explanation_for_finding
    import dataclasses
    all_findings = enriched + misconfig_findings
    explained = []
    for f in all_findings:
        exp = get_explanation_for_finding(f.module, f.target_service)
        if exp and f.explanation is None:
            f = dataclasses.replace(f, explanation=exp)
        explained.append(f)

    # 9. ASSESS — risk_scorer
    from core.risk_scorer import score_findings
    scored = score_findings(explained)

    # 10. SAVE — persister les Findings finaux
    save_findings(scored + misconfig_findings)
    # Mettre à jour risk_score en DB pour chaque Finding scoré
    from core.database import update_finding_risk_score
    for f in scored:
        if f.risk_score is not None:
            update_finding_risk_score(session_id, f.id, f.risk_score)

    # 11. Fermer la session
    close_session(session_id)

    # 12. Afficher le résumé
    _render_scan_summary(session_id, scored + misconfig_findings)
```

### Gestion des erreurs par étape

Chaque étape est dans un `try/except` individuel avec `display([yellow]...[/yellow])`.
Si `device_fingerprint` échoue → on affiche un avertissement et on continue
avec les étapes qui ne dépendent pas des hôtes actifs.
Si une étape échoue → les Findings déjà sauvegardés restent en DB.

### Confirmation

La confirmation globale est demandée UNE FOIS au début du scan.
Les modules individuels (tcp_scan, udp_scan) ont leurs propres confirmations
— pour le pipeline automatique, on peut leur passer `auto_confirm=True`
si leur signature le supporte, sinon on intercepte via l'option `--yes`.

**Option `--yes` / `-y`** : skip toutes les confirmations intermédiaires.
Sans `--yes`, chaque module demande sa propre confirmation.

---

## 2. `netlab sentinel start/status/stop`

```python
@sentinel_app.command("start")
def sentinel_start(
    target: str = typer.Option(..., "--target", "-t"),
    relearn: bool = typer.Option(False, "--relearn"),
    session: Optional[str] = typer.Option(None, "--session"),
):
    from sentinel.sentinel_manager import start
    start(target_network=target, session_id=session, force_relearn=relearn)


@sentinel_app.command("status")
def sentinel_status(
    session: str = typer.Option(..., "--session", "-s"),
):
    from sentinel.sentinel_manager import status, display_status
    display_status(session)


@sentinel_app.command("stop")
def sentinel_stop(
    session: str = typer.Option(..., "--session", "-s"),
):
    from sentinel.sentinel_manager import stop
    stop(session)
```

---

## 3. `netlab report generate`

```python
@report_app.command("generate")
def report_generate(
    session: str = typer.Option(..., "--session", "-s"),
    format: str = typer.Option("json", "--format", "-f"),
    output: Optional[str] = typer.Option(None, "--output", "-o",
        help="Output file path. Default: ~/.netlab/reports/<session>.<format>"),
):
    from reports.generator import generate_report
    from pathlib import Path

    if output is None:
        out_dir = Path.home() / ".netlab" / "reports"
        out_dir.mkdir(parents=True, exist_ok=True)
        output = str(out_dir / f"{session}.{format}")

    ok = generate_report(session_id=session, format=format, output_path=output)
    if ok:
        display(f"[green]Report saved:[/green] {output}")
    else:
        raise typer.Exit(code=1)
```

---

## 7. PipelineResult — état en mémoire du pipeline

```python
@dataclass
class StepResult:
    name: str
    status: str          # "ok" | "partial" | "failed"
    detail: str = ""     # message libre
    failed_hosts: list = field(default_factory=list)

@dataclass
class PipelineResult:
    steps: List[StepResult] = field(default_factory=list)
    findings_count: int = 0
    global_score: Optional[float] = None

    @property
    def overall_status(self) -> str:
        if all(s.status == "ok" for s in self.steps):
            return "SUCCESS"
        if any(s.status == "failed" for s in self.steps
               if s.name in ("session", "discover")):
            return "FAILED"
        if any(s.status in ("partial", "failed") for s in self.steps):
            return "PARTIAL"
        return "SUCCESS"
```

**Pas de nouvelle table DB.** L'état du pipeline est en mémoire uniquement, le temps du scan.

## 8. Affichage du résumé

```
✓ Session créée            (session-abc123)
✓ 4 hôtes découverts
✓ TCP scan : 4/4 réussis
⚠ UDP scan : 3/4 réussis
  └─ 192.168.1.25 : échec du scan UDP
✓ CVE enrichment
⚠ Misconfiguration detection : 3/4 réussis
  └─ 192.168.1.30 : analyse échouée
✓ 7 Findings générés
✓ Risk scoring
✓ Résultats enregistrés

────────────────────────
RÉSULTAT : PARTIAL
────────────────────────
⚠ 2 opérations ont échoué.
```

Trois statuts finaux :
- `SUCCESS` → tout s'est correctement exécuté
- `PARTIAL` → résultats produits mais certaines opérations ont échoué
- `FAILED` → impossible d'obtenir un résultat exploitable (session ou discover échoués)

**Règle fondamentale (cohérence A3) :**
`0 findings après scan réussi` ≠ `0 findings parce que discover a échoué`.
Le résumé doit toujours indiquer la cause réelle d'un résultat vide.

---

## 5. Ce qui ne change pas

- Toutes les fonctions des modules (signatures inchangées)
- core/finding.py, core/database.py, core/risk_scorer.py — inchangés
- Les sous-commandes `findings list/show/explain` — déjà fonctionnelles

---

## 6. Impact sur les tests CLI existants

`tests/test_cli.py` : les tests du scan vont changer car le scan appelle
maintenant de vrais modules. Il faut mocker `fingerprint`, `tcp_scan`,
`udp_scan`, `enrich_findings`, `detect_misconfigs`, `score_findings`,
`save_findings` pour que les tests restent unitaires.

Les tests `netlab sentinel` et `netlab report generate` passent de
"vérifie le message stub" à "vérifie l'appel au bon module".
