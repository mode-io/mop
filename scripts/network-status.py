"""Report observed adapter freshness and service failures without exposing secrets."""
import json
import os
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]


def read_status(path, now=None):
    try:
        with path.open('rb') as stream:
            raw = stream.read(65537)
        if len(raw) > 65536:
            raise ValueError('Oversized status')
        value = json.loads(raw)
        stamp = float(value['updated_at'])
        age = (time.time() if now is None else now) - stamp
        value['status_fresh'] = 0 <= age < 10
        return value
    except (OSError, ValueError, KeyError, TypeError):
        return {'status': 'unavailable', 'status_fresh': False}


def service_status(name):
    fields = ('ActiveState', 'SubState', 'Result', 'NRestarts', 'MemoryCurrent', 'MemoryMax')
    try:
        result = subprocess.run(['systemctl', 'show', name, *['--property=' + key for key in fields]],
                                capture_output=True, text=True, timeout=3, check=True)
        values = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
        return {key: values[key] for key in fields if key in values}
    except (OSError, subprocess.SubprocessError):
        return {'status': 'unavailable'}


def main():
    network = ROOT / '.runtime/network'
    uid = str(os.getuid())
    report = {name: read_status(path) for name, path in (
        ('passive', Path('/var/log/mop-content') / uid / 'status.json'),
        ('proxy', network / 'status.json'), ('tcp_proxy', network / 'tcp/status.json'))}
    report['services'] = {name: service_status(name) for name in (
        'mop-content-' + uid, 'mop-network-' + uid, 'mop-network-tcp-' + uid, 'mop-tetragon')}
    report['reverse_routes'] = {folder.name: read_status(folder / 'status.json')
                                for folder in sorted(network.glob('reverse-[0-9]*'))[:16]}
    report['last_validation'] = {}
    for path in sorted(network.glob('validation-*.json'))[:32]:
        try:
            with path.open('rb') as stream:
                raw = stream.read(65537)
            if len(raw) > 65536:
                continue
            value = json.loads(raw)
            report['last_validation'][path.stem] = {
                'verified_at': value.get('verified_at'), 'all_verified': value.get('all_verified'),
                'report': str(path), 'historical_result_not_current_health': True}
        except (OSError, ValueError, TypeError, AttributeError):
            continue
    report['boundaries'] = {
        'proxy_requires_routing_and_ca_trust': True, 'http3': 'explicit_reverse_route_quic_v1',
        'certificate_pinning': 'not_bypassed', 'custom_encryption': 'opaque_without_application_adapter',
        'quic_v2': 'not_supported', 'arbitrary_dtls': 'not_verified',
        'protobuf': 'wire_values_without_application_field_names', 'ssh': 'connection_metadata_only'}
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
