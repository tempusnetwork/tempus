# tempus
# To-do

## High prio

* Re-adapt mutual_add to use signatures or pubkey validation
* Fix the chain: Limit to X months or whatever, relay chain to new peers, smart update when offline for 10 hrs etc 
* Write out complete blockception protocol together with timestamp
* Why would anyone forward others pings? Only incentivized to forward own pings (to get highest uptime)

## Medium prio

* Malicious intent on ?addr and ?redistributions in URL query
* Figure out proper consensus mechanism, including reference to previous hash (and potential collisions)
* Need to add rogue client which tries to attack the network in as many ways as possible
* What if rogue peer sends fake port? Can do a mirror ddos?

## Rest

* Fix all too broad excepts..
* Make more secure way of retrieving private key
* Fix repeated redundant rehashing done for retrieving hash list with hash()
* Smarter rehashing (C or C++) + mining + similarity score validation
* Smarter genesis hash/structure
* Sanitize input/better schema validation
* Dns seed
* Remove fullpeers