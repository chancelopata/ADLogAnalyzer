'''ADLogAnalyzer
Usage:
    ADLogAnalyzer.py <logFilePath> [--ignoreIPs=<IP>... --ignoreUsers=<USER>... --countryWhitelist=<COUNTRYCODE>... (--abuseIPDB=<KEY> <THRESHOLD>) (--abuseIPDBCache=<filePath>) --out=<PATH>]
    ADLogAnalyzer.py -h | --help
    ADLogAnalyzer.py --version

Options:
    --logFilePath: Path to log file
    --ignoreIP: Ignore these IP addresses.
    --ignoreUser: Ignore these users
    --countryWhitelist: Treat all other countries as dangerous. Accepts 2 letter code.
    --abuseIPDB <KEY> <THRESHOLD>: Key used in abuseIPDB lookup and threshhold is the minimum number of failed sign ins from an IP required to launch a API request to abuseIPDB.
    --abuseIPDBCache <filePath>: Use a file to cache abuseipdb api responses. If it exists, the program will check all queries to be made against the cache to make sure it is not querying info it already has. Any new info will be saved to the file. A file is created if none exists.
    --out: Path for output.
'''

from docopt import docopt
import pandas as pd
from xlsxwriter import Workbook
import requests
from threading import Thread
from pathlib import Path

pd.options.mode.chained_assignment = None

VERSION = "1.0"

# Performs API call for an IP against abuseipdb then returns the 'data' portion of the json response.
def checkAbuseIPDB(IP: str, apiKey: str) -> dict:
    r = requests.get(
        'https://api.abuseipdb.com/api/v2/check?ipAddress='+IP+'&maxAgeInDays=90&verbose',
        headers={'Key' : apiKey, 'Accept': 'application/json'}
    )
    r = r.json()['data']
    return r

# Parse arguments from command
args = docopt(__doc__)

if args["--version"]:
    print("ADLogAnalyzer " + VERSION)
    quit()

logFilePath = Path(args['<logFilePath>']) #TODO: use Pathlib with all file paths here.
ignoreIPs = args['--ignoreIPs']
ignoreUsers = args['--ignoreUsers']
countryWhitelist = args['--countryWhitelist']
abuseIPDBKey = args['--abuseIPDB']
abuseIPDBCacheFile = args['--abuseIPDBCache']
out = args['--out']
threshold = args['<THRESHOLD>']

if threshold:
    threshold = int(threshold)


# Read in cache file if exists, if not then create a blank one.
abuseIP_df = None
if abuseIPDBCacheFile is not None:
    abuseIPDBFile = Path(abuseIPDBCacheFile)
    if abuseIPDBFile.is_file():
        abuseIP_df = pd.read_csv(abuseIPDBCacheFile)
    else:
        Path(abuseIPDBCacheFile).touch()
        abuseIP_df = pd.DataFrame()

# Read in AAD logs. Abort if bad path.
df = None
if logFilePath.is_file():
    df = pd.read_csv(logFilePath)
else:
    print('Fatal error - File does not exist at relative path: ' + logFilePath.name)
    quit()

dangerousCountries = ['KR','KP','NK','CN','JP','RU']

####################################
# Clean df by removing unwanted data
####################################

# Drop traffic that we do not care about that is specific to the this set of logs
if ignoreUsers:
    df = df[~df.User.isin(ignoreUsers)]
if ignoreIPs:
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
dangerousCountrySignIns = pd.DataFrame()
IPsAboveThreshold = pd.DataFrame()
susFailedSignIns = df[['User','IP','Status']]

# Get a list of users with failed sign ins and each IP they used.
susFailedSignIns = susFailedSignIns[susFailedSignIns.Status == 'Failure']
susFailedSignIns = susFailedSignIns.rename(columns={'Status':'Failures'})

#####################
# AbuseIPDB API calls
#####################
if abuseIPDBKey is not None:
    susFailedSignIns = susFailedSignIns.groupby(['User','IP']).count().reset_index()
    IPsAboveThreshold = susFailedSignIns[susFailedSignIns['Failures'] >= threshold]
    IPsAboveThreshold = IPsAboveThreshold['IP']

    # Create df of unique IPs so we dont duplicate queries
    IPsAboveThreshold = IPsAboveThreshold.drop_duplicates()
    IPsAboveThreshold = IPsAboveThreshold.reset_index()
    UniqueIPs = IPsAboveThreshold['IP']
    
    if len(UniqueIPs) != 0:
        APIResponses = list()
    
        # Don't repeat requests for info we already have. Create empty abuseIP_df if there was not one to begin with.
        if not abuseIP_df.empty:
            UniqueIPs = UniqueIPs[~UniqueIPs.isin(abuseIP_df['IP'])]

        # Make API requests, get responses in list. Do this seperate from df because pandas is not thread safe.
        for ip in UniqueIPs:
            APIResponses.append(checkAbuseIPDB(ip,abuseIPDBKey))

        if  abuseIP_df.empty:
            abuseIP_df = pd.DataFrame([APIResponses[0]])
            abuseIP_df = abuseIP_df.iloc[0:0]
            abuseIP_df = abuseIP_df.rename(columns={'ipAddress':'IP'})

        # Make df from new api responses
        tmp_df = pd.DataFrame(APIResponses)

        # Combine new responses with old ones if they exist.
        abuseIP_df = pd.concat([abuseIP_df,tmp_df])
        abuseIP_df['IP'] = abuseIP_df['IP'].fillna('')
            # Combine two ip collumns if needed
        if 'ipAddress' in abuseIP_df.columns:
            abuseIP_df['ipAddress'] = abuseIP_df['ipAddress'].fillna('')
            abuseIP_df['IP'] = abuseIP_df['IP']+abuseIP_df['ipAddress']

        # Filter out what we dont want 
        abuseDataToKeep = ['IP','abuseConfidenceScore','countryCode','countryName','usageType','isp','domain','isTor']
        abuseIP_df = abuseIP_df[abuseDataToKeep]

        # Join abuseipdb info with df of failed sign ins.
        susFailedSignIns = susFailedSignIns.merge(abuseIP_df, on='IP', how='left')

        
        # This makes the excel file easier to read. All it does is get rid of redundant names. Might want to sacrifice it for speed.
        #susFailedSignIns = susFailedSignIns.groupby(['User','IP','countryCode','abuseScore','isp','usageType']).sum() 
else:
    susFailedSignIns = susFailedSignIns.groupby(['User','IP']).count()

# Get all sign ins from dangerous countries
if  countryWhitelist:
    dangerousCountrySignIns = df.loc[~df['Country'].isin(countryWhitelist)]
    dangerousCountrySignIns = dangerousCountrySignIns.drop_duplicates()
else:
    dangerousCountrySignIns = df.loc[df['Country'].isin(dangerousCountries)]
    dangerousCountrySignIns = dangerousCountrySignIns.drop_duplicates()

#############################
# Write df's to excel sheets
#############################
writer = pd.ExcelWriter
if out:
    writer = pd.ExcelWriter(out, engine='xlsxwriter')
else:   
    writer = pd.ExcelWriter(logFilePath.name + '_analyzed.xlsx', engine='xlsxwriter')
df.to_excel(writer, sheet_name='Filtered')
dangerousCountrySignIns.to_excel(writer, sheet_name='DangerousCountry')
susFailedSignIns.to_excel(writer, sheet_name='FailedSignIns')
writer.close()

#############################
# Store API call info
#############################
if abuseIPDBFile is not None:
    abuseIP_df.to_csv(abuseIPDBCacheFile.name)