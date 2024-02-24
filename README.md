## Welcome

This is a small IPAM tool I have developed in my free time.

It relies on the **ping** utility as external resource and the **jinja2** module, the rest is pure python. I have used **Python 3.11** during development, but it should be good backwards with a couple of versions.

In order to use it you simply have to clone it.

It uses a **sqlite3** backend to store **subnets** and **status** tables.

The following schema is used for the **status** table.

``` sql
CREATE TABLE status (
id INTEGER PRIMARY KEY AUTOINCREMENT,
address TEXT,
dns TEXT,
ping INTEGER,
timestamp TEXT);
```

The following schema is used for the **subnets** table.

``` sql
CREATE TABLE subnets (
id INTEGER PRIMARY KEY AUTOINCREMENT,
subnet TEXT,
description TEXT,
status INTEGER);
```

The following schema is used for the **overrides** table.

``` sql
CREATE TABLE overrides (
id INTEGER PRIMARY KEY AUTOINCREMENT,
address TEXT,
dns TEXT);
```

In order to use the tool you have to clone the repositroy, and install the dependency from the **requirements.txt** file.

``` bash
git clone https://github.com/r3ap3rpy/PyPAM
cd PyPAM
pip install -r requirements.txt
```

Then you will have to perform the following actions:
- Initialize the database.
- Add subnets for checking.
- Add overrides if you feel it necessary.
- Run it on-demand or schedule it so it runs at your time of need.
- Optionally you can generate a static site from the information stored in your database!

During execution the tool used threading to speed up the process. The default is the number of cores made visible by the **os.cpu_count()** function call. 

## TODO
- [ ] Add simple filter for the subnet tables!
- [x] Add Description column to the subnets table.
- [x] Make sure overlapping subnets don't result in double checks.
- [x] Add cli arguments to manage overrides.
- [x] Add override possibility for DNS, in case ping works but DNS fails.
- [x] Add threading to name resolution and ping!
- [x] Make sure ping utility follows palatform
- [x] Setup threading so all available cores of CPU are used!
- [x] Subnet validation
