import pymysql
import subprocess
import socket
import sys
from datetime import datetime

DB_HOST = 'localhost'
DB_USER = 'firewall_admin'
DB_PASS = 'DB_PASS'
DB_NAME = 'db_firewall'


def run_iptables(cmd):
    """Exécute une commande iptables avec gestion d'erreur"""
    result = subprocess.run(
        ['iptables'] + cmd,
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        print(f"[ERREUR IPTABLES] {' '.join(cmd)}")
        print(result.stderr.strip())
        return False

    return True


def flush_custom_rules():
    """Réinitialise proprement la chaîne FIREWALL_RULES"""
    subprocess.run(['iptables', '-F', 'FIREWALL_RULES'], capture_output=True)
    subprocess.run(['iptables', '-X', 'FIREWALL_RULES'], capture_output=True)
    run_iptables(['-N', 'FIREWALL_RULES'])

    result = subprocess.run(
        ['iptables', '-C', 'FORWARD', '-j', 'FIREWALL_RULES'],
        capture_output=True
    )

    if result.returncode != 0:
        run_iptables(['-I', 'FORWARD', '1', '-j', 'FIREWALL_RULES'])


def resolve_domain(domain):
    """Résout un domaine en combinant socket et dig pour maximiser les IPs"""
    ips = set()

    try:
        for info in socket.getaddrinfo(domain, None, socket.AF_INET):
            ips.add(info[4][0])
    except socket.gaierror:
        pass

    try:
        result = subprocess.run(
            ['dig', '+short', domain, 'A'],
            capture_output=True, text=True
        )
        for line in result.stdout.splitlines():
            line = line.strip()
            if line and line[0].isdigit():
                ips.add(line)
    except Exception:
        pass

    if not ips:
        print(f"[ERREUR DNS] Impossible de résoudre {domain}")

    return list(ips)


def apply_rules():
    flush_custom_rules()

    try:
        conn = pymysql.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASS,
            database=DB_NAME
        )
    except Exception as e:
        print("[ERREUR DB]", e)
        sys.exit(1)

    cursor = conn.cursor()

    # Créer l'entrée de sync
    cursor.execute(
        "INSERT INTO sync_logs (success, rules_applied, message) VALUES (%s, %s, %s)",
        (False, 0, "En cours...")
    )
    conn.commit()
    sync_id = cursor.lastrowid

    # Récupérer les règles
    cursor.execute("""
        SELECT c.ip_address, r.destination, r.rule_type, r.action 
        FROM firewall_rules r 
        JOIN clients c ON r.client_id = c.id
    """)

    errors = []
    rules_count = 0

    for client_ip, destination, rule_type, action in cursor.fetchall():
        target = 'DROP' if action == 'deny' else 'ACCEPT'
        resolved_ips = []

        if rule_type == 'domain':
            ips = resolve_domain(destination)
            resolved_ips = ips
            for ip in ips:
                if target == 'DROP':
                    run_iptables([
                        '-A', 'FIREWALL_RULES',
                        '-s', client_ip,
                        '-d', ip,
                        '-j', 'LOG',
                        '--log-prefix', '[FW_BLOCKED] ',
                        '--log-level', '4'
                    ])
                if not run_iptables([
                    '-A', 'FIREWALL_RULES',
                    '-s', client_ip,
                    '-d', ip,
                    '-j', target
                ]):
                    errors.append(f"Echec: {client_ip} -> {ip}")
                else:
                    rules_count += 1

        elif rule_type in ('ip', 'cidr'):
            resolved_ips = [destination]
            if target == 'DROP':
                run_iptables([
                    '-A', 'FIREWALL_RULES',
                    '-s', client_ip,
                    '-d', destination,
                    '-j', 'LOG',
                    '--log-prefix', '[FW_BLOCKED] ',
                    '--log-level', '4'
                ])
            if not run_iptables([
                '-A', 'FIREWALL_RULES',
                '-s', client_ip,
                '-d', destination,
                '-j', target
            ]):
                errors.append(f"Echec: {client_ip} -> {destination}")
            else:
                rules_count += 1

        # Log de chaque règle
        cursor.execute(
            """INSERT INTO firewall_logs 
            (client_ip, destination, rule_type, action, resolved_ips, sync_id) 
            VALUES (%s, %s, %s, %s, %s, %s)""",
            (client_ip, destination, rule_type, action, ','.join(resolved_ips), sync_id)
        )

    # Mettre à jour le sync_log
    success = len(errors) == 0
    error_msg = '\n'.join(errors) if errors else None
    message = f"[SUCCESS] {rules_count} règles appliquées" if success else f"[WARNING] {rules_count} règles appliquées, {len(errors)} erreurs"

    cursor.execute(
        "UPDATE sync_logs SET success = %s, rules_applied = %s, errors = %s, message = %s WHERE id = %s",
        (success, rules_count, error_msg, message, sync_id)
    )

    conn.commit()
    cursor.close()
    conn.close()

    print(message)


if __name__ == '__main__':
    apply_rules()