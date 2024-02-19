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
- [ ] Add threading to name resolution and ping!
- [ ] Validate if adding subnets will result in an overlap!
- [x] Make sure ping utility follows palatform
- [x] Setup threading so all available cores of CPU are used!
- [x] Subnet validation
