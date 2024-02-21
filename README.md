## Welcome

This is a small IPAM tool I have developed in my free time.

It relies on the **ping** utility as external resource, the rest is pure python. I have used **Python 3.11** during development, but it should be good backwards with a couple of versions.

In order to use it you simply have to clone it.

It uses a **sqlite3** backend to store **subnets** and **status** tables.

The following schema is used for the **status** table.

``` sql
CREATE TABLE status (
id INTEGER PRIMARY KEY AUTOINCREMENT,
address TEXT,
dns TEXT,
ping integer,
timestamp TEXT);
```

The following schema is used for the **subnets** table.

``` sql
CREATE TABLE subnets (
id INTEGER PRIMARY KEY AUTOINCREMENT,
subnet TEXT,
status INTEGER);
```




## TODO
- [x] Make sure overlapping subnets don't result in double checks.
- [x] Add cli arguments to manage overrides.
- [x] Add override possibility for DNS, in case ping works but DNS fails.
- [x] Add threading to name resolution and ping!
- [x] Make sure ping utility follows palatform
- [x] Setup threading so all available cores of CPU are used!
- [x] Subnet validation
