## Open Nodes

Open Nodes is a crawler that attempts to map out all nodes of crypto currencies based on the bitcoin protocol.

A flask web server is included to display the data.

You will need to download the 3 geoip files (cities, countries, and ASN) from the maxmind site - this requires registration. Copy the .mmdb files into the `geoip` directory

### Usage (Docker)
```
docker-compose up
```
### Usage
```
# Install python virtual environment
apt install python3-pip python3-venv
python3 -m venv venv
source venv/bin/activate

# Install packages (Python 3)
# psycopg2-binary is required for postgres support
# uwsgi is required for nginx/apache deployment
pip install -r requirements.txt

# setup geoip database
cd geoip && ./update.sh && cd ..

# run crawler
python crawler.py --seed --crawl --dump

# run development flask server
python app.py
```

The `--seed` parameter is only needed for the first run or when adding a new network. It will hit all the DNS seeds specified in the config file, as well as all individual seeder nodes (if applicable)

The `--crawl` parameter iterates through all known nodes and stores them in the specified database

The `--dump` parameter writes all data to disk in json, csv, and txt format for ingestion by the webserver

IPv6 Nodes will only be reachable if you have IPv6 Routing available. To set up IPv6 routing on an AWS deployment see [here](https://www.dogsbody.com/blog/setting-up-ipv6-on-your-ec2/)

Onion Nodes will only be reachable if you have a Tor server running (`apt install tor`)

### Deployment
The crawler is best run via cron jobs, `--dump` instances should be scheduled separately from `--crawl` jobs. 

`flock` should be used to prevent multiple instances from running concurrently

For production use, the default database (sqlite) should not be used, as the file lock timeout will prevent simultaneous crawling, dumping, and reporting/api calls.

### NGINX deployment

`wsgi.py` and `flask.ini` are included for nginx deployment. You will need to `pip install uwsgi` and then set up a system service (see https://www.digitalocean.com/community/tutorials/how-to-serve-flask-applications-with-uwsgi-and-nginx-on-ubuntu-16-04)

```
nano /etc/systemd/system/opennodes.service
```

and add

``` 
[Unit]
Description=OpenNodes uWSGI instance
After=network.target

[Service]
User= {{ USERNAME }}
Group=www-data
WorkingDirectory=/home/{{ PROJECT ROOT }}
Environment="PATH=/home/{{ PATH TO PYTHON/VENV BIN DIR }}"
ExecStart=/home/{{ PATH TO PYTHON/VENV BIN DIR }}/uwsgi --ini flask.ini

[Install]
WantedBy=multi-user.target

```

Now you need to add nginx configuration to handle proxy requests

```
nano /etc/nginx/sites-available/opennodes
```
and add

``` 
server {
    listen 80;
    server_name {{ SERVER DOMAIN OR IP }};
    
    location / {
        include uwsgi_params;
        uwsgi_pass unix:///home/{{ PROJECT ROOT }}/opennodes.sock;
    }
}
```
Where the domain/ip is likely 127.0.0.1

Then add a symbolic link, remove the default configuration, and restart nginx

```
ln -s /etc/nginx/sites-available/opennodes /etc/nginx/sites-enabled
rm /etc/nginx/sites-enabled/default
systemctl restart nginx
```
