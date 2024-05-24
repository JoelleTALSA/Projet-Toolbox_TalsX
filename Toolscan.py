import nmap
import vulners
import paramiko
import logging
from prettytable import PrettyTable
import argparse

# Initialisation des outils
nm = nmap.PortScanner()
vulners_api = vulners.Vulners(api_key='YOUR_VULNERS_API_KEY')

# Configurer le logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class Toolbox:
    def __init__(self, target, username, passwords):
        self.target = target
        self.username = username
        self.passwords = passwords

    # 1. Découverte de ports et de services
    def discover_ports_and_services(self):
        logging.info("Starting port and service discovery.")
        nm.scan(self.target, '1-65535')
        services = {}
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                lport = nm[host][proto].keys()
                for port in lport:
                    service = nm[host][proto][port]['name']
                    state = nm[host][proto][port]['state']
                    services[port] = {'service': service, 'state': state}
        return services

    # 2. Détection de vulnérabilités
    def detect_vulnerabilities(self, services):
        logging.info("Starting vulnerability detection.")
        vulnerabilities = {}
        for port, info in services.items():
            try:
                results = vulners_api.search(f'{info["service"]}')
                vulnerabilities[port] = results
            except Exception as e:
                vulnerabilities[port] = str(e)
        return vulnerabilities

    # 3. Analyse de la sécurité des mots de passe
    def analyze_password_security(self):
        logging.info("Starting password security analysis.")
        weak_passwords = [pwd for pwd in self.passwords if len(pwd) < 8]
        return weak_passwords

    # 4. Tests d'authentification
    def test_authentication(self):
        logging.info("Starting authentication tests.")
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        for password in self.passwords:
            try:
                client.connect(self.target, username=self.username, password=password)
                return True, password
            except paramiko.AuthenticationException:
                continue
        return False, None

    # 5. Exploitation de vulnérabilités (simulation simple)
    def exploit_vulnerabilities(self, vulnerabilities):
        logging.info("Starting vulnerability exploitation.")
        exploited = {}
        for port, vulns in vulnerabilities.items():
            if vulns:
                exploited[port] = 'Exploit attempted'
            else:
                exploited[port] = 'No vulnerabilities found'
        return exploited

    # 6. Post-exploitation (simulation simple)
    def post_exploitation(self):
        logging.info("Starting post-exploitation.")
        sensitive_data = {'files': ['/etc/passwd', '/etc/shadow']}
        return sensitive_data

    # 7. Reporting
    def generate_report(self, services, vulnerabilities, weak_passwords, authenticated, exploited, sensitive_data):
        logging.info("Generating report.")
        report = PrettyTable()
        report.field_names = ["Port", "Service", "State", "Vulnerabilities", "Exploited", "Sensitive Data"]
        for port, info in services.items():
            report.add_row([
                port,
                info['service'],
                info['state'],
                vulnerabilities.get(port, 'None'),
                exploited.get(port, 'None'),
                sensitive_data.get('files', 'None') if port in exploited else 'N/A'
            ])
        print(report)

# Utilisation de la toolbox avec des arguments de ligne de commande
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Automated Intrusion Testing Toolbox')
    parser.add_argument('target', help='Target IP address')
    parser.add_argument('username', help='Username for authentication tests')
    parser.add_argument('passwords', nargs='+', help='List of passwords for authentication tests')
    args = parser.parse_args()

    toolbox = Toolbox(args.target, args.username, args.passwords)

    services = toolbox.discover_ports_and_services()
    vulnerabilities = toolbox.detect_vulnerabilities(services)
    weak_passwords = toolbox.analyze_password_security()
    authenticated, password_used = toolbox.test_authentication()
    exploited = toolbox.exploit_vulnerabilities(vulnerabilities)
    sensitive_data = toolbox.post_exploitation()

    toolbox.generate_report(services, vulnerabilities, weak_passwords, authenticated, exploited, sensitive_data)

    if authenticated:
        logging.info(f'Successful authentication with password: {password_used}')
    else:
        logging.info('Authentication failed with all provided passwords.')



