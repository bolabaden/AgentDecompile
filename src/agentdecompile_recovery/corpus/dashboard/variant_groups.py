"""Non-destructive variant views derived from completed comparison evidence."""
from __future__ import annotations

import json
from typing import Any

from .common import live_db, live_root, query_db

# Conservative display policy, not an identity or byte-proof acceptance gate.
MIN_MATCHES = 20
MIN_COVERAGE = 0.20


def annotate_variant_groups(binaries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_path = {path: row for row in binaries for path in row.get('sourcePaths', [row.get('repo')]) if path}
    by_id = {row['id']: row for row in binaries}
    inventories, error = query_db('SELECT b.repo_path,b.md5,COUNT(f.id) FROM binary b LEFT JOIN func f ON f.binary_id=b.id GROUP BY b.id')
    inventory = {row[0]: list(row) for row in inventories} if not error else {}
    evidence: dict[tuple[int, int], dict[str, Any]] = {}
    root = live_root()
    paths = (root / 'preparations' / 'comparisons').glob('*/*.json') if root else []
    for path in paths:
        try:
            receipt = json.loads(path.read_text())
            src, dst = receipt['source'], receipt['target']
            if receipt.get('jobStatus') != 'ok' or receipt.get('db') != str(live_db()):
                continue
            if src not in by_path or dst not in by_path or src not in inventory or dst not in inventory:
                continue
            expected = sorted([inventory[src], inventory[dst]], key=lambda row: row[0])
            if receipt.get('inventory') != expected:
                continue
            a, b = by_path[src]['id'], by_path[dst]['id']
            if a == b:
                continue
            result = receipt.get('result') or {}
            # Job payloads may nest the command result; only structured counts qualify.
            if not isinstance(result, dict):
                continue
            if 'counts' not in result and isinstance(result.get('result'), dict):
                result = result['result']
            counts = result.get('counts')
            if not isinstance(counts, dict):
                continue
            accepted = int(counts.get('auto', 0))
            source_total, target_total = int(result.get('src_funcs', 0)), int(result.get('dst_funcs', 0))
            if min(source_total, target_total) <= 0:
                continue
            coverage = min(accepted / source_total, accepted / target_total)
            pair = tuple(sorted((a, b)))
            item = {'source': src, 'target': dst, 'acceptedMatches': accepted,
                    'sourceFunctions': source_total, 'targetFunctions': target_total,
                    'minimumCoverage': coverage, 'jobId': receipt.get('jobId'),
                    'related': accepted >= MIN_MATCHES and coverage >= MIN_COVERAGE,
                    'completedAt': receipt.get('completedAt') or 0,
                    'claim': 'advisory', 'receipt': str(path)}
            if pair not in evidence or item['completedAt'] > evidence[pair]['completedAt']:
                evidence[pair] = item
        except (OSError, ValueError, TypeError, KeyError):
            continue
    # Complete-link grouping prevents a shared-library bridge from merging families.
    groups: list[list[int]] = []
    for binary_id in sorted(by_id):
        for group in groups:
            if all(evidence.get(tuple(sorted((binary_id, other))), {}).get('related') for other in group):
                group.append(binary_id)
                break
        else:
            groups.append([binary_id])
    for group in groups:
        members = [by_id[value] for value in group]
        for row in members:
            comparisons = [item for pair, item in evidence.items() if row['id'] in pair]
            status = 'related' if len(group) > 1 else ('insufficient' if comparisons else 'pending')
            row['variant_group'] = {
                'id': 'variants-' + str(min(group)),
                'label': ('Related variants · ' + str(members[0].get('label') or members[0]['slug'])) if len(group) > 1 else ('Insufficient variant evidence' if comparisons else 'Awaiting comparison'),
                'status': status, 'members': [member['slug'] for member in members],
                'evidence': comparisons, 'claim': 'advisory',
                'policy': {'minimumAcceptedMatches': MIN_MATCHES, 'minimumCoverageEachBuild': MIN_COVERAGE,
                           'description': 'Every pair in a group must meet both limits. Missing or stale comparisons never establish separation.'},
            }
    return binaries
