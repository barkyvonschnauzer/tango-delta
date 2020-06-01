import json
import os

from azure.cosmos import CosmosClient
from datetime import datetime

####################
# GLOBAL VARIABLES #
####################

##########################################################################
#
# Function name: main
# Input: None.
# Output: TBD
#
# Purpose: Connect to COSMOS DB and compute delta of malicious URLs
#
##########################################################################
def main():

    print ("**** COMPUTE DELTA FOR MALICIOUS URLS ****\n")

    results = get_records_from_cosmos()
    deltas = get_delta(results)
    store_deltas(deltas)

##########################################################################
#
# Function name: get_records_from_cosmos
# Input: None.
# Output: TBD
#
# Purpose: Connect to COSMOS DB and pull the two most recent records.
#
##########################################################################
def get_records_from_cosmos():

    latest_2_query_results = []

    print ("**** GET RECORDS FROM COSMOS ****")
    uri = os.environ.get('ACCOUNT_URI')
    key = os.environ.get('ACCOUNT_KEY')
    database_id = os.environ.get('DATABASE_ID')
    container_id = os.environ.get('RESULTS_CONTAINER_ID')
   
    client = CosmosClient(uri, {'masterKey': key})
    print (client)

    database = client.get_database_client(database_id)
    container = database.get_container_client(container_id)

    latest_2_query_results = list(container.query_items(query = 'SELECT TOP 2 * FROM c ORDER BY c._ts DESC', enable_cross_partition_query = True))    

    for result in latest_2_query_results:
        print (json.dumps(result, indent=True))

    return latest_2_query_results

##########################################################################
#
# Function name: get_delta
# Input: None.
# Output: TBD
#
# Purpose: Get delta from records retrieved from cosmos.
#
##########################################################################
def get_delta(records):

    print ("**** FIND DELTA FUNCTION ****")

    # record fields of interest:
    #'phishing'
    #'already_blocked'
    #'suspicious'
    #'malware'

    delta = dict()

    keys = [
        'phishing',
        'already_blocked',
        'suspicious',
        'malware'
    ]

    if len(records) == 2:
        # record[0] is most recent.  
        # Want to identify what is in record[0], but not in record[1]
        record_1 = records[0]
        record_2 = records[1]

        print ("Record #1: ")
        print (json.dumps(record_1, indent=True))
        print ("Record_#2: ")
        print (json.dumps(record_2, indent=True))

        for k in keys:
            delta[k] = set(records[0][k].split(' ')) - set(records[1][k].split(' '))

        print ("\nPHISHING DELTA\n")
        print (delta['phishing'])
        print ("\nALREADY BLOCKED DELTA\n")
        print (delta['already_blocked'])
        print ("\nSUSPICIOUS DELTA\n")
        print (delta['suspicious'])
        print ("\nMALWARE DELTA\n")
        print (delta['malware'])

    else:
        for k in keys:
            delta[k] = set()

    return delta 


##########################################################################
#
# Function name: store_deltas
# Input: Deltas.
# Output: TBD
#
# Purpose: Store deltas in the cosmos tango-delta container.
#
##########################################################################
def store_deltas(delta):

    print ("**** STORE DELTAS IN COSMOS DB ****")
    uri          = os.environ.get('ACCOUNT_URI')
    key          = os.environ.get('ACCOUNT_KEY')
    database_id  = os.environ.get('DATABASE_ID')
    container_id = os.environ.get('DELTA_CONTAINER_ID')

    client = CosmosClient(uri, {'masterKey': key})

    database = client.get_database_client(database_id)
    container = database.get_container_client(container_id)

    # Get date
    date_str = datetime.today().strftime('%Y-%m-%d %H:%M:%S')
    id_date  = int((datetime.utcnow()).timestamp())
    id_date_str = str(id_date)

    phishing_delta = list(delta['phishing'])
    already_blocked_delta = list(delta['already_blocked'])
    suspicious_delta = list(delta['suspicious'])
    malware_delta = list(delta['malware'])

    all_unique_list = list(set(phishing_delta) | set(already_blocked_delta) | set(suspicious_delta) | set(malware_delta))

    all_phishing_delta_str        = ' '.join(map(str, phishing_delta))
    all_already_blocked_delta_str = ' '.join(map(str, already_blocked_delta))
    all_suspicious_delta_str      = ' '.join(map(str, suspicious_delta))
    all_malware_delta_str         = ' '.join(map(str, malware_delta))
    all_unique_str                = ' '.join(map(str, all_unique_list))

    container.upsert_item( { 'id': id_date_str,
                             'date_time': id_date_str,
                             'date': date_str,
                             'n_unique': str(len(all_unique_list)),
                             'unique' : all_unique_str,
                             'n_phishing': str(len(phishing_delta)),
                             'phishing_delta': all_phishing_delta_str,
                             'n_blocked_delta': str(len(already_blocked_delta)),
                             'already_blocked_delta': all_already_blocked_delta_str,
                             'n_suspicious_delta': str(len(suspicious_delta)),
                             'suspicious_delta': all_suspicious_delta_str,
                             'n_malware_delta': str(len(malware_delta)),
                             'malware_delta': all_malware_delta_str })


if __name__ == "__main__":
    main()
