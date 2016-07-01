# passport_example
Investigating passport and mongo

## Install mongo db server
sudo ./install_mongo.sh


## Basic mongo command
1. Start & stop service
sudo service mongodb start
sudo service mongodb stop
sudo service mongodb restart

2. Access to mongo DB management server
mongo

3. Basic mongo commands
db.help()
db.stats()
show dbs;
use DB_NAME
show collections;
db.COLLECTION_NAME.find().pretty()


