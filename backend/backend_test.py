# small test program to randomly select 100 hosts and request them thru the API

import pandas as pd
import requests

hosts = pd.read_csv("../csv_tables/hosts.csv")

counter = 0

for ip in hosts["ip"].sample(n=100): # change n to the number of hosts you want to test, default 100
    req = requests.post("http://localhost:8000/host", json={"ip": ip})
    print("host ", counter, ip)
    counter += 1