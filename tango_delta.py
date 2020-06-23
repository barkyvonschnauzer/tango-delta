import csv
import json
import os

from azure.cosmos import CosmosClient
from datetime import datetime
from pathlib import Path


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

    results_tango, results_netcraft = get_records_from_cosmos()
    deltas_tango, deltas_netcraft = get_delta(results_tango, results_netcraft)
    store_deltas(deltas_tango, deltas_netcraft)


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
    results_container_id = os.environ.get('RESULTS_CONTAINER_ID')
    dummy_container_id = os.environ.get('DUMMY_CONTAINER_ID')
   
    client = CosmosClient(uri, {'masterKey': key})
    print (client)

    database = client.get_database_client(database_id)
    tango_container = database.get_container_client(results_container_id) # Results limited to those submitted by UUID
    netcraft_container = database.get_container_client(dummy_container_id) # Results include redirects, all results reported in portal 

    latest_2_query_results_tango = list(tango_container.query_items(query = 'SELECT TOP 2 * FROM c ORDER BY c._ts DESC', enable_cross_partition_query = True))    
    latest_2_query_results_netcraft = list(netcraft_container.query_items(query = 'SELECT TOP 2 * FROM c ORDER BY c._ts DESC', enable_cross_partition_query = True))

    for result in latest_2_query_results_tango:
        print (json.dumps(result, indent=True))

    for result in latest_2_query_results_netcraft:
        print (json.dumps(result, indent=True))

    return latest_2_query_results_tango, latest_2_query_results_netcraft

##########################################################################
#
# Function name: get_delta
# Input: None.
# Output: TBD
#
# Purpose: Get delta from records retrieved from cosmos.
#
##########################################################################
def get_delta(records_tango, records_netcraft):

    print ("**** FIND DELTA FUNCTION ****")

    # record fields of interest:
    #'phishing'
    #'already_blocked'
    #'suspicious'
    #'malware'

    delta_tango    = dict()
    delta_netcraft = dict()

    if len(records_tango) == 2:
        keys = [
            'phishing',
            'already_blocked',
            'suspicious',
            'malware'
            ]

        # record[0] is most recent.  
        # Want to identify what is in record[0], but not in record[1]
        record_1 = records_tango[0]
        record_2 = records_tango[1]

        print ("Record #1: ")
        print (json.dumps(record_1, indent=True))
        print ("Record_#2: ")
        print (json.dumps(record_2, indent=True))

        for k in keys:
            delta_tango[k] = set(records_tango[0][k].split(' ')) - set(records_tango[1][k].split(' '))

        print ("\nPHISHING DELTA\n")
        print (delta_tango['phishing'])
        print ("\nALREADY BLOCKED DELTA\n")
        print (delta_tango['already_blocked'])
        print ("\nSUSPICIOUS DELTA\n")
        print (delta_tango['suspicious'])
        print ("\nMALWARE DELTA\n")
        print (delta_tango['malware'])

    else:
        for k in keys:
            delta_tango[k] = set()

    if len(records_netcraft) == 2:
        record_1 = records_netcraft[0]['netcraft_results']
        record_2 = records_netcraft[1]['netcraft_results']

        attack_urls_1 = []
        attack_urls_2 = []

        for entry in record_1:
            attack_urls_1.append(entry['attack_url'])

        for entry in record_2:
            attack_urls_2.append(entry['attack_url'])

        print (set(attack_urls_1))
        print (set(attack_urls_2))

        delta_netcraft = []

        # record[0] is most recent.
        # Want to identify what is in record[0], but not in record[1] 
        delta_netcraft.append(set(attack_urls_1) - set(attack_urls_2))

        print ("\nNETCRAFT ATTACK URLS DELTA\n")
        print (delta_netcraft[0])


    return delta_tango, delta_netcraft[0]


##########################################################################
#
# Function name: store_deltas
# Input: Deltas.
# Output: TBD
#
# Purpose: Store deltas in the cosmos tango-delta container.
#
##########################################################################
def store_deltas(delta_tango, delta_netcraft):

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

    phishing_delta = list(delta_tango['phishing'])
    already_blocked_delta = list(delta_tango['already_blocked'])
    suspicious_delta = list(delta_tango['suspicious'])
    malware_delta = list(delta_tango['malware'])

    tango_unique_list = list(set(phishing_delta) | set(already_blocked_delta) | set(suspicious_delta) | set(malware_delta))

    #print (type(tango_unique_list))
    #print (type(delta_netcraft))

    delta_netcraft_list = list(delta_netcraft)
    all_unique_list = tango_unique_list + delta_netcraft_list

    all_unique_list_str           = ' '.join(map(str, all_unique_list))
    all_phishing_delta_str        = ' '.join(map(str, phishing_delta))
    all_already_blocked_delta_str = ' '.join(map(str, already_blocked_delta))
    all_suspicious_delta_str      = ' '.join(map(str, suspicious_delta))
    all_malware_delta_str         = ' '.join(map(str, malware_delta))
    all_unique_str                = ' '.join(map(str, all_unique_list))
    all_netcraft_delta_str        = ' '.join(map(str, delta_netcraft_list))

    container.upsert_item( { 'id': id_date_str,
                             'date_time': id_date_str,
                             'date': date_str,
                             'n_unique': str(len(all_unique_list)),
                             'unique' : all_unique_list_str,
                             'n_phishing': str(len(phishing_delta)),
                             'phishing_delta': all_phishing_delta_str,
                             'n_blocked_delta': str(len(already_blocked_delta)),
                             'already_blocked_delta': all_already_blocked_delta_str,
                             'n_suspicious_delta': str(len(suspicious_delta)),
                             'suspicious_delta': all_suspicious_delta_str,
                             'n_malware_delta': str(len(malware_delta)),
                             'malware_delta': all_malware_delta_str,
                             'n_netcraft_delta': str(len(delta_netcraft_list)),
                             'netcraft_delta': all_netcraft_delta_str })

    
    write_attack_urls_to_output(all_unique_list, tango_unique_list, delta_netcraft_list, date_str)


##########################################################################
#
# Function name: write_attack_urls_to_output
# Input: TBD
# Output: TBD
#
# Purpose: TBD
#
##########################################################################
def write_attack_urls_to_output(all_results, tango_results, netcraft_results, date_str):
    print ("**** WRITE LIST OF ATTACK URLS TO OUTPUT ****")

    output_filename_all      = "Attack_URL_List_ALL_" + (date_str.replace(':','-')).replace(' ','_')
    output_filename_tango    = "Attack_URL_List_TANGO_" + (date_str.replace(':','-')).replace(' ','_')
    output_filename_netcraft = "Attack_URL_List_NETCRAFT_" + (date_str.replace(':','-')).replace(' ','_')
    delta_filename_csv       = "TANGO_Current_Delta.csv" 
    
    output_filepath_all      = Path('/output') / output_filename_all
    output_filepath_tango    = Path('/output') / output_filename_tango
    output_filepath_netcraft = Path('/output') / output_filename_netcraft
    delta_filepath_csv       = Path('/output') / delta_filename_csv

    print (output_filepath_all)
    print (output_filepath_tango)
    print (output_filepath_netcraft)
    print (delta_filepath_csv)

    print ('Write ALL:')
    with open(output_filepath_all, 'w') as all_output_fh:
        for url in set(all_results):
            print (url)
            all_output_fh.write('%s\n' % url)

    print ('Write TANGO:')
    with open(output_filepath_tango, 'w') as tango_output_fh:
        for url in set(tango_results):
            print (url)
            tango_output_fh.write('%s\n' % url)

    print ('Write NETCRAFT:')
    with open(output_filepath_netcraft, 'w') as netcraft_output_fh:
        for url in set(netcraft_results):
            print (url)
            netcraft_output_fh.write('%s\n' % url)

    # delete delta file if it exists
    if os.path.exists(delta_filepath_csv):
        print ("Deleting TANGO_Current_Delta.csv")
        os.remove(delta_filepath_csv)
    else:
        print ("TANGO_Current_Delta.csv does not exist")

    print ('Write DELTA to CSV:')

    # Now write to it
    open(delta_filepath_csv, 'w').close()

    with open(delta_filepath_csv, 'w') as delta_csv_output_file:
        delta_output_csv_writer = csv.writer(delta_csv_output_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
        delta_output_csv_writer.writerow(all_results)

if __name__ == "__main__":
    main()
