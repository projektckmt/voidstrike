---
name: ad-attack-paths
description: High-leverage BloodHound Cypher queries for finding short paths to Domain Admins and adjacent attack chains.
allowed-tools: [ad__bloodhound_query]
---

# AD attack paths — high-leverage queries

After `ad__bloodhound_collect` has ingested data, these queries surface the
attack paths that matter. Run in roughly this order; each result is a
candidate plan.

## Shortest path to Domain Admins

```cypher
MATCH p = shortestPath((a)-[*1..]->(g:Group {name: 'DOMAIN ADMINS@DOMAIN'}))
WHERE a.owned = true
RETURN p LIMIT 10
```

Substitute `DOMAIN` for the actual domain. `a.owned` flags accounts you have
control of — BloodHound supports `MATCH (u:User {name:'...'}) SET u.owned = true`.

## Kerberoastable accounts

```cypher
MATCH (u:User)
WHERE u.hasspn = true
RETURN u.name, u.serviceprincipalnames
```

For each, run `ad__kerberoast` to grab the hash; offline crack.

## ASREProastable accounts

```cypher
MATCH (u:User {dontreqpreauth: true})
RETURN u.name
```

For each, run `ad__asreproast` — these don't require valid creds.

## Unconstrained delegation hosts

```cypher
MATCH (c:Computer {unconstraineddelegation: true})
RETURN c.name
```

These are gold for printer-bug / coerced-auth chains. Pair with
`PetitPotam` / `MS-RPRN` coercions to relay against another host.

## Generic-All over users

```cypher
MATCH (a)-[r:GenericAll]->(u:User)
WHERE a.owned = true
RETURN a.name, u.name
```

ACL abuse: as `a`, you can reset `u`'s password.

## DCSync-capable accounts

```cypher
MATCH (a)-[:MemberOf*1..]->(g:Group)
WHERE g.name CONTAINS 'DOMAIN CONTROLLERS' OR g.name STARTS WITH 'ENTERPRISE ADMINS'
RETURN a.name, labels(a)
```

Members can DCSync. From a DCSyncer, `ad__dcsync` for `krbtgt` enables
golden-ticket forging.

## Don't blindly execute

Each query produces *candidates*. Before executing the attack:

1. Check the path makes sense (is the next-hop actually reachable?).
2. Check the action class — kerberoast/dcsync trigger HITL in engagement mode.
3. Capture creds; let the orchestrator chain to lateral movement after HITL.
