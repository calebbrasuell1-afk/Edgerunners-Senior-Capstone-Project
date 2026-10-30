import sqlite3
import pandas as pd

# connect to db
sql_db = sqlite3.connect('data/network.db')

# query the database to get all available tables as Dataframes
# this takes forever, but it works. will look into potential performance issues 
db_flows = pd.read_sql_query('Select * from flows;', sql_db)
db_edges = pd.read_sql_query('Select * from edges;', sql_db)
db_hosts = pd.read_sql_query('Select * from hosts;', sql_db)
db_buckets = pd.read_sql_query('Select * from host_buckets;', sql_db)
db_events = pd.read_sql_query('Select * from gt_events;', sql_db)
db_regions = pd.read_sql_query('Select * from detector_regions;', sql_db)
db_closed_types = pd.read_sql_query('Select * from pair_close_types_parsed;', sql_db)

print("Tables loaded")

"""
Extract the timeframes 
"""
def extract_detections
