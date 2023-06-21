import requests
import json
from bs4 import BeautifulSoup
import time
import pathlib

class Audit:

    def __init__(self, domain):
        self.domain = domain

    def inspect_hackertarget_hostsearch(self):
        response = requests.get(f'https://api.hackertarget.com/hostsearch/?q={self.domain}').text
        response = response.splitlines()
        result = []
        for line in response:
            if line == 'API count exceeded - Increase Quota with Membership':  # 50 reqs per day API limitation
                break
            domain, ip = line.split(',', 1)
            result.append({
                'domain': domain,
                'ip': ip
            })
        with open('hackertarget.json', 'w') as f:
            json.dump(result, f)
        return response

    def inspect_crt_sh(self):
        table = []
        NUM_RETRIES = 5  # Sometimes I randomly got 502 Gateway without a reason (server issue?)
        for attempt in range(1, NUM_RETRIES + 1):
            response = requests.get(f'https://crt.sh/?q={self.domain}')
            if response.status_code == 502:
                print(f'inspect_crt_sh test: Got 502 status Response code. '
                      f'Trying again 15 sec delay. Attempt {attempt}/{NUM_RETRIES})')
                time.sleep(15)
                continue
            else:
                soup = BeautifulSoup(response.content, 'html.parser')
                table = soup.select('td.outer')

        if not table:
            return []

        elif table[1].i:
            if table[1].i.getText() == 'None found':
                result = {
                    'success': False,
                    'message': 'None found'
                }
                with open('crt_sh.json', 'w') as f:
                    json.dump(result, f)

                return result
        else:
            table = table[1]
            table = table.table
            rows = table.find_all('tr')
            strings = []
            for row in rows:
                cols = row.find_all('td')
                cols = [x.text.strip() for x in cols]
                strings.append(cols)
            strings.pop(0)
            result = []
            for string in strings:
                result.append({
                    'crt_sh_id': string[0],
                    'logged_at': string[1],
                    'not_before': string[2],
                    'not_after': string[3],
                    'issuer_name': string[4]
                })
            with open('crt_sh.json', 'w') as f:
                json.dump(result, f)

            return result

    def inspect_certspotter(self):
        response = requests.get(f'https://api.certspotter.com/v1/issuances?domain={self.domain}').json()
        with open('certspotter.json', 'w') as f:
            json.dump(response, f)
        return response

    def union_files(self):
        with open("certspotter.json", 'r') as file_1:
            data_certspotter = json.load(file_1)

        with open('crt_sh.json', 'r') as file_2:
            data_crt_sh = json.load(file_2)

        with open('hackertarget.json', 'r') as file_3:
            data_hacker_target = json.load(file_3)

        data_final = {
            "data_certspotter": data_certspotter,
            "data_crt_sh": data_crt_sh,
            "data_hacker_target": data_hacker_target,
        }

        root_path = pathlib.Path(__file__).parent
        file_path = root_path.joinpath('result.json')
        file_path.write_text(json.dumps(data_final))



