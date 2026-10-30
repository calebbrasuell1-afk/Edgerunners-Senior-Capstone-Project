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

# Extract the timeframes of potential detections from the events table.
potential_detection_events = db_regions["region_id", "attack_type", "known_name", "category", "t_min", "t_max"]

# known events, ground truth
ground_truth_events = db_events["c2s_id", "event_type", "start_utc", "stop_utc"]

# TODO iterate through all events and create tuple pairs of time frames (with id) to quickly be added to the visualization

