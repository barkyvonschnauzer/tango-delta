import azure.cosmos.cosmos_client as cosmos_client

import numpy as np
import os
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
    #phishing, already_blocked, suspicious, malware = get_delta(results)
    #store_deltas(phishing, already_blocked, suspicious, malware)
    
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

    print ("**** GET RECORDS FROM COSMOS ****")
    uri = os.environ.get('ACCOUNT_URI')
    key = os.environ.get('ACCOUNT_KEY')
    database_id = os.environ.get('DATABASE_ID')
    container_id = os.environ.get('RESULTS_CONTAINER_ID')

    client = cosmos_client.CosmosClient(uri, {'masterKey': key})
    print (client)

    container_link = "dbs/" + str(database_id) + "/colls/" + str(container_id)
    print ("Container link: " + container_link)

    query = 'SELECT TOP 2 * FROM c ORDER BY c._ts DESC'
    print (query)

    latest_2_query_results = list(client.QueryItems(container_link, query, {"enableCrossPartitionQuery": True}))

    for result in latest_2_query_results:
        print (result)

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
#def get_delta(records):
#
#    print ("**** FIND DELTA FUNCTION ****")
#
#    record_1 = records[0]
#    record_2 = records[1]
#
#    print ("Record #1: ")
#    print (record_1)
#    print ("Record_#2: ")
#    print (record_2)
#
#    # record fields:
#    #'date'
#    #'uuids'
#    #'n_phishing'
#    #'phishing'
#    #'n_blocked'
#    #'already_blocked'
#    #'n_nothreat'
#    #'nothreat'
#    #'n_suspicious'
#    #'suspicious'
#    #'n_malware'
#    #'malware'
#    #'n_processing'
#    #'processing'
#    #'n_unavailable'
#    #'unavailable'
#    #'n_rejected'
#    #'rejected'
#
#    # extract the phishing, already_blocked, suspicious, and malware entries
#    phishing_1 = record_1['phishing']
#    phishing_2 = record_2['phishing']
#    already_blocked_1 = record_1['already_blocked']
#    already_blocked_2 = record_2['already_blokced']
#    suspicious_1 = record_1['suspicious']
#    suspicious_2 = record_2['suspicious']
#    malware_1 = record_1['malware_1']
#    malware_2 = record_2['malware_2']
#
#    # convert space-delimited strings to lists
#    phishing_1_list = map(str, phishing_1.split(' '))
#    phishing_2_list = map(str, phishing_2.split(' '))
#
#    already_blocked_1_list = map(str, already_blocked_1.split(' '))
#    already_blocked_2_list = map(str, already_blocked_2.split(' '))
#
#    suspicious_1_list = map(str, suspicious_1.split(' '))
#    suspicious_2_list = map(str, suspicious_2.split(' '))
#
#    malware_1_list = map(str, malware_1.split(' '))
#    malware_2_list = map(str, malware_2.split(' '))
#
#    # identify what is in the new list, but not the old one
#    phishing_delta = np.setdiff1d(phishing_1_list, phishing_2_list)
#    already_blocked_delta = np.setdiff1d(already_blocked_1_list, already_blocked_2_list)
#    suspicious_delta = np.setdiff1d(suspicious_1_list, suspicious_2_list)
#    malware_delta = np.setdiff1d(malware_1_list, malware_2_list)
#
#    print ("\nPHISHING DELTA\n")
#    print (phishing_delta)
#    print ("\nALREADY BLOCKED DELTA\n")
#    print (already_blocked_delta)
#    print ("\nSUSPICIOUS DELTA\n")
#    print (suspicious_delta)
#    print ("\nMALWARE DELTA\n")
#    print (malware_delta)
#
#    #return


##########################################################################
#
# Function name: store_deltas
# Input: Deltas.
# Output: TBD
#
# Purpose: Store deltas in the cosmos tango-delta container.
#
##########################################################################
#def store_deltas(phishing_delta, already_blocked_delta, suspicious_delta, malware_delta):
#
#    print ("**** STORE DELTAS IN COSMOS DB ****")
#    print ("\n***** Add UUID to the COSMOS DB *****\n")
#    uri          = os.environ.get('ACCOUNT_URI')
#    key          = os.environ.get('ACCOUNT_KEY')
#    database_id  = os.environ.get('DATABASE_ID')
#    container_id = os.environ.get('DELTA_CONTAINER_ID')
#
#    client = cosmos_client.CosmosClient(uri, {'masterKey': key})
#    container_link = "dbs/" + str(database_id) + "/colls/" + str(container_id)
#    print ("Container link: " + container_link)
#
#    # Get date
#    date_str = datetime.today().strftime('%Y-%m-%d %H:%M:%S')
#    id_date  = int((datetime.utcnow()).timestamp())
#    id_date_str = str(id_date)
#
#    all_phishing_delta_str        = ' '.join(map(str, phishing_delta))
#    all_already_blocked_delta_str = ' '.join(map(str, already_blocked_delta))
#    all_suspicious_delta_str      = ' '.join(map(str, suspicious_delta))
#    all_malware_delta_str         = ' '.join(map(str, malware_delta))
#
#    client.UpsertItem(container_link, { 'id': id_date_str,
#                                        'date': date_str,
#                                        'n_phishing': str(len(phishing_delta)),
#                                        'phishing_delta': all_phishing_delta_str,
#                                        'n_blocked_delta': str(len(already_blocked_delta)),
#                                        'already_blocked_delta': all_already_blocked_delta_str,
#                                        'n_suspicious_delta': str(len(suspicious_delta)),
#                                        'suspicious_delta': all_suspicious_delta_str,
#                                        'n_malware_delta': str(len(malware_delta)),
#                                        'malware_delta': all_malware_delta_str })


if __name__ == "__main__":
    main()
