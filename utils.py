import argparse
from typing import Union

import requests


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--domain', required=True, type=str,
                        help='domain [example.xyz]')
    return parser.parse_args()


def request(url: str, method: str = 'GET') -> Union[None, requests.Response]:
    try:
        resp = requests.request(method=method, url=url, verify=False)
        if resp.status_code == 200:
            return resp
    except requests.exceptions.RequestException as e:
        print(f'Error: {e}')


def clear_domain(domain: str) -> str:
    return domain.replace('www.', '', 1) if domain.startswith('www.') else domain
