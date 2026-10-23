"""Fail closed on unclassified findings and incomplete vulnerability metadata."""
import json
from pathlib import Path
import subprocess
import sys


def scan(command, **kwargs):
    command = list(map(str, command))
    severity = command.index('--severity') + 1
    command[severity] = ','.join(dict.fromkeys(command[severity].split(',') + ['UNKNOWN']))
    report = Path(command[command.index('--output') + 1])
    report.unlink(missing_ok=True)
    result = subprocess.run(command, stderr=subprocess.PIPE, text=True, **kwargs)
    detail = result.stderr or ''
    report.with_suffix(report.suffix + '.stderr.log').write_text(detail)
    sys.stderr.write(detail)
    result.check_returncode()
    if any(marker in detail.lower() for marker in (
            'unable to get vulnerability details', 'no vulnerability details', 'failed to get vulnerability')):
        raise RuntimeError('Scanner vulnerability details are incomplete; promotion is blocked')
    data = json.loads(report.read_text())
    if any(v.get('Severity', 'UNKNOWN') in ('HIGH', 'CRITICAL', 'UNKNOWN')
           for row in data.get('Results', []) or [] for v in row.get('Vulnerabilities', []) or []):
        raise RuntimeError('High/Critical or unclassified vulnerability blocks promotion')
    return result
