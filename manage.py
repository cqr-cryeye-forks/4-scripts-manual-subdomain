import requests
import sys


from source import Audit


domain = sys.argv[1]

audit = Audit(domain)

# audit.inspect_threat_crowd()
audit.inspect_hackertarget_hostsearch()
audit.inspect_crt_sh()
audit.inspect_certspotter()
