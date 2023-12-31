'''ADLogAnalyzer
Usage:
    ADLogAnalyzer.py <logFilePath> [--ignoreIPs=<IP> --ignoreUsers=<USER> --watchUsers=<USER> --countryWhitelist=<COUNTRYCODE> (--abuseIPDB=<KEY> <THRESHOLD>) (--abuseIPDBCache=<filePath> [--maxAge=<DAYS>]) --out=<PATH>]
    ADLogAnalyzer.py -h | --help
    ADLogAnalyzer.py --version

Options:
    --logFilePath: Path to log file. Must be in json or csv format.
    --ignoreIP: Ignore these IP addresses. Accepted as a single string seperated by commas.
    --ignoreUser: Ignore these users. Accepted as a single string seperated by commas.
    --countryWhitelist: Treat all other countries as dangerous. Accepts 2 letter code.
    --abuseIPDB <KEY> <THRESHOLD>: Key used in abuseIPDB lookup and threshhold is the minimum number of failed sign ins from an IP required to launch a API request to abuseIPDB.
    --abuseIPDBCache <filePath>: Use a file to cache abuseipdb api responses. If it exists, the program will check all queries to be made against the cache to make sure it is not querying info it already has. Any new info will be saved to the file. A file is created if none exists.
    --maxAge <DAYS>: data in the cache file older than <DAYS> will be deleted and requeried to get fresh data.
    --out: Path for output.
    --watchUsers: Get all successes for these users. Will watch users even if their IP or User is supposed to be ignored via --ignoreIP or --ignoreUsers. Accepted as a single string seperated by commas.
'''

from docopt import docopt
import pandas as pd
import requests
from pathlib import Path
from datetime import datetime, timedelta
from multiprocessing.pool import ThreadPool
from itertools import repeat

# Performs API call for an IP against abuseipdb then returns the 'data' portion of the json response with the date the query was made added to it.
def checkAbuseIPDB(IP: str, apiKey: str) -> dict:
    r = requests.get(
        'https://api.abuseipdb.com/api/v2/check?ipAddress='+IP+'&maxAgeInDays=90&verbose',
        headers={'Key' : apiKey, 'Accept': 'application/json'}
    )
    r = r.json()['data']
    r['queryDate'] = datetime.utcnow()
    return r

if __name__ == '__main__':
    pd.options.mode.chained_assignment = None

    VERSION = "1.0"

    dangerousCountrySignIns = pd.DataFrame()
    IPsAboveThreshold = pd.DataFrame()
    watchedSignIns = pd.DataFrame()
    df = None

    # Parse arguments from command and format them for convenience if neccessary.
    args = docopt(__doc__)

    if args["--version"]:
        print("ADLogAnalyzer " + VERSION)
        quit()
    logFilePath = Path(args['<logFilePath>']) #TODO: use Pathlib with all file paths here.
    ignoreIPs = args['--ignoreIPs']
    ignoreUsers = args['--ignoreUsers']
    watchUsers = args['--watchUsers']
    countryWhitelist = args['--countryWhitelist']
    abuseIPDBKey = args['--abuseIPDB']
    cacheFile = args['--abuseIPDBCache']
    maxAge = args['--maxAge']

    if ignoreIPs:
        ignoreIPs = ignoreIPs.split(',')
    if ignoreUsers:
        ignoreUsers = ignoreUsers.split(',')
    if watchUsers:
        watchUsers = watchUsers.split(',')
    if countryWhitelist:
        countryWhitelist = countryWhitelist.split(',')

    now = datetime.utcnow()
    concurrent = 30

    # Check if maxAge is properly set, if not then quit.
    if maxAge:
        try:
            maxAge = timedelta(days=int(maxAge))
        except ValueError:
            quit()

    if cacheFile is not None:
        cacheFile = Path(args['--abuseIPDBCache'])
    
    out = args['--out']
    threshold = args['<THRESHOLD>']

    if threshold:
        threshold = int(threshold)

    # Read in cache file if exists, if not then create a blank one.
    abuseIP_df = None
    if cacheFile is not None:
        if cacheFile.is_file():
            try:
                abuseIP_df = pd.read_csv(cacheFile)
            except(pd.errors.EmptyDataError):
                print("FATAL ERROR: Can't read cache file - Corrupted file or bad files path?")
                quit()
            
            abuseIP_df['queryDate'] = pd.to_datetime(abuseIP_df['queryDate'])
            # Get rid of old queries.
            if(maxAge):
                oldestAcceptableDate = now - maxAge
                if(maxAge):
                    abuseIP_df = abuseIP_df.loc[oldestAcceptableDate <= abuseIP_df['queryDate']]
        else:
            cacheFile.touch()
            abuseIP_df = pd.DataFrame()
    else:
        abuseIP_df = pd.DataFrame()

    # Read in AAD logs. Abort if bad path.
    if logFilePath.is_file():
            with open(logFilePath) as f:
                if f.read(1) == '{':
                    pd.read_json(logFilePath)
                else:
                    df = pd.read_csv(logFilePath)
        
    else:
        print('FATAL ERROR: log File not found at path: ' + logFilePath.name)
        quit()

    dangerousCountries = ['KR','KP','NK','CN','JP','RU']

    ####################################
    # Clean df by removing unwanted data
    ####################################

    # Normalize data
    df[['City','State/province','Country']] = df['Location'].str.split(',',expand=True)

    cols = ['City','State/province','Country']
    for col in cols:
        df[col] = df[col].str.strip()

    # Select data to keep
    df['IP'] = df['IP address']
    dataToKeep = ['Date (UTC)', 'User','IP', 'City', 'State/province','Country' ,'Status','Client app']
    df = df[dataToKeep]

    # watching user should include ignored stuff.
    if watchUsers:
        watchedSignIns = df[['User','IP','Status']]

    # Drop traffic that we do not care about that is specific to the this set of logs
    if ignoreUsers:
        df = df[~df.User.isin(ignoreUsers)]
    if ignoreIPs:
        df = df[~df['IP'].isin(ignoreIPs)]

    ############################
    # Generate Interesting Data
    ############################

    susFailedSignIns = df[['User','IP','Status']]

    # Get a list of users with failed sign ins and each IP they used.
    susFailedSignIns = susFailedSignIns[susFailedSignIns.Status == 'Failure']
    susFailedSignIns = susFailedSignIns.rename(columns={'Status':'Failures'})

    # Get all successes for useres provided in --watchUsers switch.
    if watchUsers:
        watchedSignIns = watchedSignIns[watchedSignIns.User.isin(watchUsers)]
        watchedSignIns = watchedSignIns[watchedSignIns.Status == "Success"]


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
            with ThreadPool(concurrent) as pool:
                APIResponses = pool.starmap(checkAbuseIPDB, zip(UniqueIPs, repeat(abuseIPDBKey)), 1)

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
            abuseDataToKeep = ['IP','abuseConfidenceScore','countryCode','countryName','usageType','isp','domain','isTor','queryDate']
            abuseIP_df = abuseIP_df[abuseDataToKeep]

            # Join abuseipdb info with df of failed sign ins.
            susFailedSignIns = susFailedSignIns.merge(abuseIP_df, on='IP', how='left')
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

    if watchUsers:
        watchedSignIns.to_excel(writer, sheet_name='WatchedUsers')
    writer.close()

    #############################
    # Store API call info
    #############################
    if cacheFile is not None:
        abuseIP_df.to_csv(cacheFile.name)