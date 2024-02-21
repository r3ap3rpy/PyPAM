import logging, os, sqlite3, sys, re
from subprocess import Popen, PIPE
from logging.handlers import RotatingFileHandler
from argparse import ArgumentParser, BooleanOptionalAction
from helper import validateSubnet, validateIpv4, Collector
from ipaddress import ip_network
from shutil import which
from socket import gethostbyaddr
from platform import system
from queue import Queue
from configparser import ConfigParser


ipv4 = re.compile("^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)(\.(?!$)|$)){4}$")
CWD = os.path.sep.join(os.path.abspath(__file__).split(os.path.sep)[:-1])
DB = os.path.sep.join([CWD,'database','pypam.db'])
LOGS = os.path.sep.join([CWD,'logs'])
OVERRIDE = os.path.sep.join([CWD,'override','override.ini'])
NUM_THRDS = os.cpu_count()
TO_OVERRIDE = dict()
folders = ['database', 'logs', 'override']

for folder in folders:
    if not os.path.isdir(os.path.sep.join([CWD,folder])):
        os.mkdir(os.path.sep.join([CWD,folder]))

logging.basicConfig(format='%(asctime)s %(levelname)s :: %(message)s', level=logging.INFO)
logger = logging.getLogger('PyPAM')
handler = RotatingFileHandler(os.path.sep.join([LOGS,'pypam.logs']), mode='a', maxBytes=1000000, backupCount=100, encoding='utf-8', delay=0)
handler.setLevel(logging.INFO)
handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
logger.addHandler(handler)

parser = ArgumentParser(description = 'This tool can be used to check for valid DNS entries on a given network')
group = parser.add_mutually_exclusive_group(required = True)
group.add_argument('--initdb', action = BooleanOptionalAction, help = "Initializes the database!")
group.add_argument('--add-subnet', type = str, help = "Adds a new subnet to the database!")
group.add_argument('--remove-subnet', type = str, help = "Removes subnet from the database!")
group.add_argument('--disable-subnet', type = str, help = "Disables subnet from checking!")
group.add_argument('--enable-subnet', type = str, help = "Enables subnet for checking! ")
group.add_argument('--list-subnets', action = BooleanOptionalAction, help = "Lists the currently used networks!")
group.add_argument('--check-ipv4', type = str, help = "Checks DNS and Ping for a given Ipv4 address!")
group.add_argument('--init-override', action = BooleanOptionalAction, help = "Initializes override.ini file!")
group.add_argument('--list-overrides', action = BooleanOptionalAction, help = "Lists overrides if present!")
group.add_argument('--add-override', action = BooleanOptionalAction, help = "Adds new override or updates existing one!")
group.add_argument('--delete-override', type = str, help = "Deletes the given override from override.ini file!")
group.add_argument('--run', action= BooleanOptionalAction, help = "Executes the tool!")
args = parser.parse_args()

databases = {
    "subnets" : {
            "create_table" : """
CREATE TABLE IF NOT EXISTS subnets (
id INTEGER PRIMARY KEY AUTOINCREMENT,
subnet TEXT,
status INTEGER);
            """
        },
    "status" : {
            "create_table" : """
CREATE TABLE IF NOT EXISTS status (
id INTEGER PRIMARY KEY AUTOINCREMENT,
address TEXT,
dns TEXT,
ping INTEGER,
timestamp TEXT);
            """
        }
}

logger.info("#" * 50)
if args.initdb:
    logger.info("# Initializing database!")
    with sqlite3.connect(DB) as connection:
        for database in databases:
            logger.info(f"# Creating datase {database}, if necessary...")
            result = connection.execute(databases[database]['create_table'])
    connection.close()
    logger.info("# You may now start using the tool!")
    logger.info("#" * 50)
elif args.add_subnet:
    logger.info(f"# Validating subnet: {args.add_subnet}")
    try:
        validateSubnet(args.add_subnet)
        logger.info("# Subnet is valid!")
    except Exception as e:
        logger.critical(f"# The subnet is invalid because :: {e.__class__.__name__} :: {e}")
        logger.info("#" * 50)
        sys.exit(-1)
    logger.info(f"# Adding subnet {args.add_subnet} to the database, if not already there!")
    with sqlite3.connect(DB) as connection:
        exists = [ _ for _ in connection.execute(f"SELECT 1 FROM subnets WHERE subnet='{args.add_subnet}'")]
        if not exists: 
            logger.info("# No existsing record, adding...")
            result = connection.execute(f"INSERT INTO subnets (subnet, status) VALUES ('{args.add_subnet}',1)")
        else:
            logger.info(f"# Subnet: {args.add_subnet} is already present, nothing to add!")
    logger.info("#" * 50)
    connection.close()
elif args.remove_subnet:
    logger.info(f"# Validating subnet: {args.remove_subnet}")
    try:
        validateSubnet(args.remove_subnet)
    except Exception as e:
        logger.critical(f"# The subnet is invalid because :: {e.__class__.__name__} :: {e}")
        logger.info("#" * 50)
        sys.exit(-1)
    logger.info(f"# Deleting subnet: {args.remove_subnet} if present!")
    with sqlite3.connect(DB) as connection:
        exists = [ _ for _ in connection.execute(f"SELECT 1 FROM subnets WHERE subnet='{args.remove_subnet}'")]
        if exists:
            logger.info(f"# Subnet: {args.remove_subnet} is present, removing...")
            connection.execute(f"DELETE FROM subnets WHERE subnet='{args.remove_subnet}'")
        else:
            logger.info(f"# Subnet: {args.remove_subnet} is not present, nothing to remove!")
    logger.info("#" * 50)
    connection.close()
elif args.disable_subnet:
    logger.info(f"# Validating subnet: {args.disable_subnet}")
    try:
        validateSubnet(args.disable_subnet)
    except Exception as e:
        logger.critical(f"# The subnet is invalid because :: {e.__class__.__name__} :: {e}")
        logger.info("#" * 50)
        sys.exit(-1)
    logger.info(f"# Disabling subnet: {args.disable_subnet} if present!")
    with sqlite3.connect(DB) as connection:
        exists = [ _ for _ in connection.execute(f"SELECT 1 FROM subnets WHERE subnet='{args.disable_subnet}'")]
        if exists:
            logger.info(f"# Subnet: {args.disable_subnet} is present, disabling it!")
            connection.execute(f"UPDATE subnets SET status = 0 WHERE subnet = '{args.disable_subnet}'")
        else:
            logger.info(f"# Subnet: {args.disable_subnet} is not present, nothing to disable!")
    logger.info("#" * 50)
    connection.close()
elif args.enable_subnet:
    logger.info(f"# Validating subnet: {args.enable_subnet}")
    try:
        validateSubnet(args.enable_subnet)
    except Exception as e:
        logger.critical(f"# The subnet is invalid because :: {e.__class__.__name__} :: {e}")
        logger.info("#" * 50)
        sys.exit(-1)
    logger.info(f"# Enabling subnet: {args.enable_subnet} if present!")
    with sqlite3.connect(DB) as connection:
        exists = [ _ for _ in connection.execute(f"SELECT 1 FROM subnets WHERE subnet='{args.enable_subnet}'")]
        if exists:
            logger.info(f"# Subnet: {args.enable_subnet} is present, enabling it!")
            connection.execute(f"UPDATE subnets SET status = 1 WHERE subnet = '{args.enable_subnet}'")
        else:
            logger.info(f"# Subnet: {args.enable_subnet} is not present, cannot enable!")
    logger.info("#" * 50)
    connection.close()
elif args.check_ipv4:
    logger.info(f"# Validating Ipv4 address: {args.check_ipv4}")
    ping_status = False
    dns_status = False
    if not validateIpv4(args.check_ipv4):
        logger.critical("# This {args.check_ipv4} is not a valid IPV4 address!")
        logger.info("#" * 50)
        sys.exit(-1)
    logger.info("# Address is valid, checking <ping>!")
    if system() == 'Windows':
        pinger = Popen(['ping',args.check_ipv4],stdout=PIPE)
    else:
        pinger = Popen(['ping','-c',"3",args.check_ipv4],stdout=PIPE)
    pingerOut, pingerErr = pinger.communicate()
    logger.info(f"# Return code was: {pinger.returncode}")
    if pinger.returncode == 0:
        ping_status = True
    logger.info(f"# Checking DNS...")
    try:
        dns_status = gethostbyaddr(args.check_ipv4)
        logger.info(f"# DNS details: {dns_status}")
        dns_status = dns_status[0]
    except Exception as e:
        logger.critical(f"# Failed to resolve DNS, because: {e}")
        dns_status = None

    logger.info(f"# DNS was: {dns_status}")
    logger.info(f"# Address: {args.check_ipv4}, ping: {ping_status}, dns: {dns_status}")
    logger.info("#" * 50)
elif args.list_subnets:
    logger.info("# Listing currenlty recorded subnets!")
    with sqlite3.connect(DB) as connection:
        subnets = [_ for _ in connection.execute("SELECT * FROM subnets")]
        if subnets:
            logger.info("#" * 50)
            logger.info("#          Subnet           #       Status       #")
            logger.info("#" * 50)
            for subnet in subnets:
                logger.info(f"# {subnet[1]:^25} # {('Enabled' if subnet[2] else 'Disabled'):^18} #")

        else:
            logger.critical("# Currently no subnets are recorded in the database!")
    logger.info("#" * 50)
    connection.close()
elif args.list_overrides:
    logger.info("# Preparing for execution.")
    logger.info("# Checking for overrides file!")
    if os.path.isfile(OVERRIDE):
        logger.info(f"# Reading file: {OVERRIDE}")
        ini_config = ConfigParser()
        ini_config.read(OVERRIDE)
        logger.info("# Checking for OVERRIDES section")
        if 'OVERRIDES' in ini_config.sections():
            if [ _ for _ in ini_config['OVERRIDES']]:
                logger.info("# Override entries... ")
                logger.info("#" * 58)
                logger.info("#          IP           #           Override             #")
                logger.info("#" * 58)
                for entry in ini_config['OVERRIDES']:
                    TO_OVERRIDE[entry] = ini_config['OVERRIDES'][entry].upper()
                    logger.info(f"# {entry:^21} # {TO_OVERRIDE[entry]:^30} #")
                logger.info("#" * 58)
            else:
                logger.warning(f"# Section is emtpy, nothing will be overridden!")
        else:
            logger.critical("# Cannot find OVERRIDES section...")
            logger.info("#" * 50)
            sys.exit(-1)
    else:
        logger.critical(f"# Cannot find {OVERRIDE}")
        logger.info("#" * 50)
        sys.exit(-1)
elif args.delete_override:
    logger.info("# Checking for overrides file!")
    if os.path.isfile(OVERRIDE):
        logger.info(f"# Reading file: {OVERRIDE}")
        ini_config = ConfigParser()
        ini_config.read(OVERRIDE)
        logger.info("# Checking for OVERRIDES section")
        if 'OVERRIDES' in ini_config.sections():
            if ini_config['OVERRIDES'].get(args.delete_override):
                logger.info(f"# Deleting {args.delete_override}")
                del ini_config['OVERRIDES'][args.delete_override]
                with open(OVERRIDE, 'w') as of:
                    ini_config.write(of)
            else:
                logger.warning("Cannot find specified override...")
                logger.info("#" * 50)
                sys.exit(-1)
        else:
            logger.critical(f"# Cannot find OVERRIDES section...")
            logger.info("#" * 50)
            sys.exit(-1)
    else:
        logger.critical(f"# Cannot find {OVERRIDE}")
        logger.info("#" * 50)
        sys.exit(-1)
elif args.init_override:
    logger.info("# Preparing for execution.")
    logger.info(f"# Checking {OVERRIDE} file, creating if necessary!")
    if not os.path.isfile(OVERRIDE):
        logger.info("# Creating file with default section!")
        with open(OVERRIDE,'w') as of:
            of.write("[OVERRIDES]\n")
        logger.info("#" * 50)
    else:
        logger.warning("# File already exists!")
        ini_config = ConfigParser()
        ini_config.read(OVERRIDE)
        logger.info("# Checking for OVERRIDES section")
        if 'OVERRIDES' in ini_config.sections():
            logger.info("# Section present!")
        else:
            logger.info("# Creating section!")
            ini_config.add_section("OVERRIDES")
            with open(OVERRIDE,'w') as of:
                ini_config.write(of)
        logger.info("#" * 50)
elif args.add_override:
    logger.info("# Preparing for execution.")
    logger.info("# Checking for overrides file!")
    if os.path.isfile(OVERRIDE):
        logger.info(f"# Reading file: {OVERRIDE}")
        ini_config = ConfigParser()
        ini_config.read(OVERRIDE)
        logger.info("# Checking for OVERRIDES section")
        if 'OVERRIDES' in ini_config.sections():
            ip_address = input("Please enter the Ipv4 address that you would like to override: ")
            if not ipv4.match(ip_address):
                logger.critical(f"The specified address: {ip_address} is invalid!")
                logger.info("#" * 50)
                sys.exit(-1)
            dns_override = input("Please specify the FQDN for this IP: ")
            if not dns_override:
                logger.critical(f"The specified address: {ip_address} is invalid!")
                logger.info("#" * 50)
                sys.exit(-1)
            logger.info(f"# Updating configuration file: {ip_address}, dns: {dns_override}")
            ini_config['OVERRIDES'][ip_address] = dns_override
            with open(OVERRIDE, 'w') as of:
                ini_config.write(of)
            logger.info("#" * 50)
        else:
            logger.critical("# Cannot find OVERRIDES section...")
            logger.info("#" * 50)
            sys.exit(-1)
else:
    logger.info("# Preparing for execution!")
    logger.info(f"# Checking for {OVERRIDE} file...")
    if os.path.isfile(OVERRIDE):
        logger.info("# Trying to read and parse override file...")
        ini_config = ConfigParser()
        ini_config.read(OVERRIDE)
        if 'OVERRIDES' in ini_config.sections():
            if [ _ for _ in ini_config['OVERRIDES']]:
                logger.info("# Override entries: ")
                for entry in ini_config['OVERRIDES']:
                    TO_OVERRIDE[entry] = ini_config['OVERRIDES'][entry].upper()
                    logger.info(f"#\t{entry} -> {TO_OVERRIDE[entry]}")
            else:
                logger.warning(f"# Section is emtpy, nothing will be overridden!")
        else:
            logger.critical("# Malformed override.ini, missing OVERRIDES section!")
    else:
        logger.info(f" # No override file was specified: {OVERRIDE}")

    logger.info("# Checking if <ping> is available!")
    if which('ping') is None:
        logger.critical("# <ping> command is not available, aborting!")
        logger.info("#" * 50)
        sys.exit(-1)
    logger.info("# <ping> is available, checking for subnets!")
    with sqlite3.connect(DB) as connection:
        subnets = [ _ for _ in connection.execute("SELECT * FROM subnets")]
        if not subnets:
            logger.critical("# There are no subnets present, aborting!")
            logger.info("#" * 50)
            sys.exit(-1)
    enabled_subnets = [ _ for _ in subnets if _[2] == 1]
    if not enabled_subnets:
        logger.critical("# There are no enabled subnets, exiting!")
        sys.exit(-1)
    logger.info("# This is the list of enabled subnets:")
    for subnet in enabled_subnets:
        logger.info(f"\t{subnet[1]}")
    logger.info(f"# Processing subnets!")
    ip_addresses = []
    for subnet in enabled_subnets:
        logger.info(f"# Working on subnet: {subnet[1]}")
        try:
            tmp = [ _ for _ in ip_network(subnet[1], strict=False)][1:-1]
            ip_addresses.extend(tmp)
        except Exception as e:
            logger.critical(f"# Skipping subnet {subnet[1]}, beacuse: {e}")

    ip_addresses = set(ip_addresses)
    if not ip_addresses:
        logger.critical(f"# Could not build up ip list to process.")
        logger.info("#" * 50)
        sys.exit(-1)

    logger.info(f"# Bulding up jobqueue!")
    jobqueue = Queue()
    resultqueue = Queue()

    for ip in ip_addresses:
        jobqueue.put(ip)

    logger.info(f"# Total number of IP addresses: {jobqueue.qsize()}")
    for i in range(NUM_THRDS):
        t = Collector(jobqueue, resultqueue, logger)
        t.daemon = True
        t.start()

    logger.info("# Waiting for the job(s) to finish!")
    jobqueue.join()

    results = []
    while not resultqueue.empty():
        results.append(resultqueue.get())
        
    logger.info(f"# Total of {len(results)} will be processed!")
    logger.info("# Updating database records!")
    for result in results:
        result[2] = (result[2].upper() if result[2] else 'N.A.' )
        logger.info(f"# Processing IP: {result[0]}, PING {result[1]}, DNS {result[2]}, Date: {result[3]}")
        with sqlite3.connect(DB) as connection:
            logger.info(f"# Checking if record exists!")
            exists = [ _ for _ in connection.execute(f"SELECT 1 FROM status WHERE address='{result[0]}'")]
            if result[1] and (result[2] == 'N.A.'):
                logger.info("# Applying override if possible!")
                if TO_OVERRIDE:
                    logger.info(f"# Overriding {result[2]} if found based on IP {result[0]}!")
                    if TO_OVERRIDE.get(str(result[0])):
                        result[2] = TO_OVERRIDE.get(str(result[0]))
                        logger.info(f"# Found, new value: {result[2]}")
            if exists:
                logger.info("# Updating record...")
                connection.execute(f"UPDATE status SET ping={result[1]}, dns='{result[2]}', timestamp='{result[3]}' WHERE address='{result[0]}'")
            else:
                logger.info("# Inserting new record...")
                connection.execute(f"INSERT INTO STATUS (address, dns, ping, timestamp) VALUES ('{result[0]}','{result[2]}',{result[1]},'{result[3]}')")
        connection.close()

