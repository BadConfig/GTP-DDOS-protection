# DDOS protection using proof of work algorithm
## Chosen algorithm and it's motivation
I've decided to choose guided tour puzzle algorithm as he is the most suitable for modern DDOS atacks protection.
Here are several arguments:
* It is secured not by computations but by network load. In distributed attacks it will be hard enough 
to allocate all machines close to the server. Moreover gudes (algorithms instances) can be phisically placed far from each other.
All these efforts lead to the fact that it will be hard to find computers that will be coping fast with requests.
* This algorithm allows for increasing number of guides and horisontally scale maximum load of the protection service
* It is designed to be stateless means small recource allocations per request
* Algorithm is non parallelizable

Algorithms [whitepaper](https://people.cs.pitt.edu/~adamlee/pubs/2012/abliz2012ijas.pdf)

## Repo's guide

Algorithm is implemented in rust and react based web client

Code contains some comments, to understand them you'd need to read the 
algorithms whitepaper or be familiar with it's contents

This system is made for demo purpose only, it has tons of nuances 
that should be modified to work in production


