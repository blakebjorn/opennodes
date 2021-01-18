## Open Nodes

Open Nodes is a crawler that attempts to map out all nodes of crypto currencies based on the bitcoin protocol.

A flask web server is included to display the data.

### Setup
You will need to download the 3 geoip files (cities, countries, and ASN) from the maxmind site - 
this requires registration.
Copy the .mmdb files into the `geoip` directory otherwise no country/ASN info will be populated

copy `.env.dist` to `.env` and change any values as necessary. Delete all database entries to use sqlite

### Usage (Docker)
```
docker-compose up
```

### Usage (Manual Installation)
```
# Install python virtual environment
apt install python3-pip python3-venv
python3 -m venv venv
source venv/bin/activate

# Install packages (Python 3)
# psycopg2-binary is required for postgres support
pip3 install -r requirements.txt

# run crawler.
python3 crawler.py --seed --crawl --dump

# run flask server
python3 app.py
```

The `--seed` parameter is only needed for the first run or when adding a new network. It will hit all the DNS seeds specified in the config file, as well as all individual seeder nodes (if applicable)

The `--crawl` parameter iterates through all known nodes and stores them in the specified database

The `--dump` parameter writes all data to disk in json, csv, and txt format for ingestion by the webserver

The `--prune` parameter removes old entries from the DB and writes them to gzipped CSVs on disk

The `--daemon` parameter does all of the above in an endless loop based on configuration

IPv6 Nodes will only be reachable if you have IPv6 Routing available. To set up IPv6 routing on an AWS deployment see [here](https://www.dogsbody.com/blog/setting-up-ipv6-on-your-ec2/)

Onion Nodes will only be reachable if you have a Tor server running (`apt install tor`)

### Deployment
The crawler can be set up as a service or via cron jobs, `--dump` instances should be scheduled separately 
from `--crawl` jobs, as they are slow to run as the DB size grows. `flock` can be used to prevent multiple 
instances from running concurrently. For production use, the default database (sqlite) should not be used, 
as the file lock timeout will prevent simultaneous crawling, dumping, and reporting/api calls.

The server runs in debug mode by default, if you pass `--prod` as an argument to `server.py` it will instead
run via waitress, and should be reverse proxied to via nginx/apache

##### Example service:
```
/etc/systemd/system/opennodes.service
```

``` 
[Unit]
Description=OpenNodes Server
After=network.target

[Service]
User= {{ USERNAME }}
Group=www-data
WorkingDirectory=/home/{{ PROJECT ROOT }}
Environment="PATH=/home/{{ PATH TO PYTHON/VENV BIN DIR }}"
ExecStart=/home/{{ PATH TO PYTHON/VENV BIN DIR }}/python3 server.py --prod

[Install]
WantedBy=multi-user.target
```
##### Example nginx config:
```
/etc/nginx/sites-enabled/opennodes
```
``` 
server {
    listen 80;
    server_name {{ SERVER DOMAIN OR IP }};
    
    location / {
        # Set proxy headers
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        proxy_pass http://localhost:8888;
    }
}