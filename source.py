import json

from utils import request, clear_domain


class Audit:

    def __init__(self, domain: str):
        self.domain = clear_domain(domain=domain)
        self.threat_crowd_url = f'https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={self.domain}'
        self.hacker_target_url = f'https://api.hackertarget.com/hostsearch/?q={self.domain}'
        self.crt_sh_url = f'https://crt.sh/?q={self.domain}&output=json'
        self.certs_potter_url = f'https://certspotter.com/api/v1/issuances?domain={self.domain}&include_subdomains=true&expand=dns_names'
        self.result = {}

    def _inspect_threat_crowd(self) -> list:
        response = request(url=self.threat_crowd_url)
        return self._parse_threat_crowd_resp(data=response.json()) if response else []

    def _inspect_hacker_target(self):
        response = request(url=self.hacker_target_url)
        return self._parse_hacker_target_resp(data=response.text) if response else []

    def _inspect_crt_sh(self):
        response = request(url=self.crt_sh_url)
        return response.json() if response else []

    def _inspect_certs_potter(self):
        response = request(url=self.certs_potter_url)
        return self._parse_certs_potter_resp(data=response.json()) if response else []

    def run(self):
        self.result['threat_crowd'] = self._inspect_threat_crowd()
        self.result['hacker_target'] = self._inspect_hacker_target()
        self.result['crt_sh'] = self._inspect_crt_sh()
        self.result['certs_potter'] = self._inspect_certs_potter()

        with open('output.json', 'w') as f:
            json.dump(self.result, f, indent=2)

    @staticmethod
    def _parse_hacker_target_resp(data: str):
        domains: list = []
        for line in data.splitlines():
            try:
                domain, ip = line.split(',', 1)
                domains.append({
                    'domain': domain,
                    'ip': ip
                })
            except ValueError:
                pass
        return domains

    @staticmethod
    def _parse_certs_potter_resp(data: dict) -> list:
        dns_names = []
        for item in data:
            dns_names.extend(item.get('dns_names', []))
        return [{'domain': item} for item in set(dns_names)]

    @staticmethod
    def _parse_threat_crowd_resp(data: dict):
        return [{'domain': item} for item in set(data.get('subdomains', []))]
