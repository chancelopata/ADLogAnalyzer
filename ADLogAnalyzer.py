'''ADLogAnalyzer
Usage:
    ADLogAnalyzer.py <logFilePath> [--ignoreIPs <IP>... --ignoreUsers <USER>... --countryWhitelist <COUNTRYCODE>... --abuseIPDB <KEY>]
    ADLogAnalyzer.py -h | --help
    ADLogAnalyzer.py --version

Options:
    --logFilePath: Path to log file
    --ignoreIP: Drop rows with these IPs 
    --ignoreUser: Drop rows with these users
    --countryWhitelist: Treat all other countries as dangerous. Accepts 2 letter code.
    --abuseIPDB: Key for using abuseIPDB lookup. Accepts file.
'''

from docopt import docopt
import pandas as pd
import os
from xlsxwriter import Workbook

pd.options.mode.chained_assignment = None

# Parse arguments from command
args = docopt(__doc__)
logFilePath = args['<logFilePath>']
ignoreIPs = args['<IP>']
ignoreUsers = args['<USER>']
safeCountryWhitelist = args['<COUNTRYCODE>']
abuseIPDBKey = args['<KEY>']

df = pd.read_csv(logFilePath)

dangerousCountries = ['KR','KP','NK','CN','JP','RU']

# Clean the df.
# Drop traffic that we do not care about that is specific to the this set of logs
if ignoreUsers is not None:
    df = df[~df.User.isin(ignoreUsers)]
if ignoreIPs is not None:
    df = df[~df['IP address'].isin(ignoreIPs)]
cleanDataFrame(df)

    
# Generate dataframes that contain data that is interesting to the analyst.
dangerousCountrySignIns = pd.DataFrame
susFailedSignIns = df[['User','IP','Status']]

# Get a list of users with failed sign ins and each IP they used.
susFailedSignIns = susFailedSignIns[susFailedSignIns.Status == 'Failure']
susFailedSignIns = susFailedSignIns.groupby(['User','IP']).count()

# Get all sign ins from dangerous countries
if safeCountryWhitelist is not None:
    dangerousCountrySignIns = df.loc[~df['Country'].isin(safeCountryWhitelist)]
    dangerousCountrySignIns = dangerousCountrySignIns.drop_duplicates()
else:
    dangerousCountrySignIns = df.loc[df['Country'].isin(dangerousCountries)]
    dangerousCountrySignIns = dangerousCountrySignIns.drop_duplicates()

# Write df's to excel sheets.
writer = pd.ExcelWriter(logFilePath + '_analyzed.xlsx', engine='xlsxwriter')
df.to_excel(writer, sheet_name='Filtered')
dangerousCountrySignIns.to_excel(writer, sheet_name='DangerousCountry')
susFailedSignIns.to_excel(writer, sheet_name='FailedSignIns')
writer.close()