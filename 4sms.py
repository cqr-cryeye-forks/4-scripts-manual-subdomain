import urllib3

from source import Audit
from utils import parse_args

urllib3.disable_warnings()


def main():
    args = parse_args()
    print('Start.')
    Audit(domain=args.domain).run()
    print('Done.')


if __name__ == '__main__':
    main()
