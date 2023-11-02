# DDOS protection using proof of work algorithm
## Chosen algorithm and it's motivation
I've decided to choose guided tour puzzle algorithm as he is the most suitable for modern DDOS atacks protection.
Here are several arguments:
* It is secured not by computations but by network load. In distributed attacks it is hard enough 
to allocate all machines close to the server. Moreover gudes (algorithms instances) can be phisically placed far from 
each other what will make vertical scailing the network access speed almost impossible.
* This algorithm allows for increasing number of guides and horisontally scale maximum load of the ddos protection service
* It is designed to be stateless and has small recource allocation per request
* Algorithm is non parallelizable
* Unlike other pow algorithms, it is cheap to complete GTP on weak hardware so users without resources won't suffer
All these efforts lead to the fact that it will be hard to find computers that will be coping fast with requests.

Algorithms [whitepaper](https://people.cs.pitt.edu/~adamlee/pubs/2012/abliz2012ijas.pdf)

## Repo's guide

Algorithm is implemented in rust and react based web client

This system is made for demo purpose only, it has tons of nuances 
that should be modified to work in production

There are tons of nuances and left issues to make this code better looking and working in prod
they are unsolved in case this is a test task and finalisation requres weeks of time

## Run 

Hopefully, docker compose will make everything for you
```sh
docker-compose up -d 
```
It will launch 3 guildes, server and a client that polls server every second completing pow 

You can also run tests and check system working there
```sh
cargo test
```
