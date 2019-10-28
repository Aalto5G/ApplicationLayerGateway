import MySQLdb
import os
import json, yaml
import uuid
from pathlib import Path

#change the path to point to the location of configuration file of ALG
source_file = Path('/home/ubuntu/config.yml')
python_obj= {}

with source_file.open('r') as f:
    json_data = json.dumps(yaml.safe_load(f))
    python_obj['ALG'] = json.loads(json_data)
    print(python_obj)

db = MySQLdb.connect(host="localhost",  # your host, usually localhost
                     user="root",  # your username
                     passwd="take5",  # your password
                     db="Bootstrap_Policies")
cur = db.cursor()

for key in python_obj:
    if key == 'ALG':
        query = "insert into bootstrap  (name, types, subtype, data) values ('{}',NULL ,NULL, '{}')".format(key, json.dumps(python_obj.get('ALG')))cur.execute(query)

db.commit()
