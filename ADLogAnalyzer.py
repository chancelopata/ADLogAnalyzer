'''ADLogAnalyzer
Usage:
    ADLogAnalyzer.py <logFilePath> [--ignoreIPs=<IP>... --ignoreUsers=<USER>... --countryWhitelist=<COUNTRYCODE>... (--abuseIPDB=<KEY> <THRESHOLD>)]
    ADLogAnalyzer.py -h | --help
    ADLogAnalyzer.py --version

Options:
    --logFilePath: Path to log file
    --ignoreIP: Ignore these IP addresses.
    --ignoreUser: Ignore these users
    --countryWhitelist: Treat all other countries as dangerous. Accepts 2 letter code.
    --abuseIPDB <KEY> <THRESHOLD>: Key used in abuseIPDB lookup and the minimum number of failed sign ins from an IP required to launch a lookup.
'''

from docopt import docopt
import pandas as pd
import os
from xlsxwriter import Workbook
import requests

pd.options.mode.chained_assignment = None

VERSION = "1.0"

# Performs API call for an IP against abuseipdb, returns full response in json
def checkAbuseIPDB(IP: str, apiKey: str) -> dict:
    r = requests.get(
        'https://api.abuseipdb.com/api/v2/check?ipAddress='+IP+'&maxAgeInDays=90&verbose',
        headers={'Key' : apiKey, 'Accept': 'application/json'}
    )
    r = r.json()['data']
    return r

# Parse arguments from command
args = docopt(__doc__)
print(args)

if args["--version"]:
    print("ADLogAnalyzer " + VERSION)
    quit()

logFilePath = args['<logFilePath>']
ignoreIPs = args['--ignoreIPs']
ignoreUsers = args['--ignoreUsers']
countryWhitelist = args['--countryWhitelist']
abuseIPDBKey = args['--abuseIPDB']

df = pd.read_csv(logFilePath)

dangerousCountries = ['KR','KP','NK','CN','JP','RU']

####################################
# Clean df by removing unwanted data
####################################

# Drop traffic that we do not care about that is specific to the this set of logs
if ignoreUsers:
    df = df[~df.User.isin(ignoreUsers)]
if ignoreIPs:
    print(10)
    df = df[~df['IP address'].isin(ignoreIPs)]

# Normalize data
df[['City','State/province','Country']] = df['Location'].str.split(',',expand=True)

cols = ['City','State/province','Country']
for col in cols:
    df[col] = df[col].str.strip()

# Select data to keep
df['IP'] = df['IP address']
dataToKeep = ['Date (UTC)', 'User','IP', 'City', 'State/province','Country' ,'Status','Client app']
df = df[dataToKeep]

############################
# Generate Interesting Data
############################
dangerousCountrySignIns = pd.DataFrame
susFailedSignIns = df[['User','IP','Status']]

# Get a list of users with failed sign ins and each IP they used.
susFailedSignIns = susFailedSignIns[susFailedSignIns.Status == 'Failure']
susFailedSignIns = susFailedSignIns.groupby(['User','IP']).count()

# Get all sign ins from dangerous countries
if  countryWhitelist:
    dangerousCountrySignIns = df.loc[~df['Country'].isin(countryWhitelist)]
    dangerousCountrySignIns = dangerousCountrySignIns.drop_duplicates()
else:
    dangerousCountrySignIns = df.loc[df['Country'].isin(dangerousCountries)]
    dangerousCountrySignIns = dangerousCountrySignIns.drop_duplicates()

if abuseIPDBKey is not None:
    pass

#############################
# Write df's to excel sheets
#############################
writer = pd.ExcelWriter(logFilePath + '_analyzed.xlsx', engine='xlsxwriter')
df.to_excel(writer, sheet_name='Filtered')
dangerousCountrySignIns.to_excel(writer, sheet_name='DangerousCountry')
susFailedSignIns.to_excel(writer, sheet_name='FailedSignIns')
writer.close()