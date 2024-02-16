import logging, os, sqlite3, sys, subprocess
from logging.handlers import RotatingFileHandler
from argparse import ArgumentParser, BooleanOptionalAction
from helper import validateSubnet, validateIpv4
from ipaddress import ip_network
from shutil import which
from socket import gethostbyaddr

CWD = os.path.sep.join(os.path.abspath(__file__).split(os.path.sep)[:-1])
DB = os.path.sep.join([CWD,'database','pypam.db'])
LOGS = os.path.sep.join([CWD,'logs'])
NUM_THRDS = os.cpu_count()

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
group.add_argument('--check-ipv4', type = str, help = "Checks DNS and Ping for a given Ipv4 address!")
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
ping INTEGER
timestamp TEXT);
            """
        }
}

if not os.path.isdir(os.path.sep.join([CWD,'database'])):
    os.mkdir(os.path.sep.join([CWD,'database']))

if not os.path.isdir(os.path.sep.join([CWD,'logs'])):
    os.mkdir(os.path.sep.join([CWD,'logs']))

logger.info("#" * 50)
if args.initdb:
    logger.info("# Initializing database!")
    with sqlite3.connect(DB) as connection:
        for database in databases:
            logger.info(f"# Creating datase {database}, if necessary...")
            result = connection.execute(databases[database]['create_table'])
    connection.close()
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
    pinger = subprocess.Popen(['ping','-c',"3",args.check_ipv4],stdout=subprocess.PIPE)
    pingerOut, pingerErr = pinger.communicate()
    logger.info(f"# Return code was: {pinger.returncode}")
    if pinger.returncode == 0:
        ping_status = True
    logger.info(f"# Checking DNS...")
    try:
        dns_status = gethostbyaddr(args.check_ipv4)[0]
    except Exception as e:
        logger.critical("# Failed to resolve DNS, because: {e}")
    logger.info(f"# DNS was: {dns_status}")
    logger.info(f"# Address: {args.check_ipv4}, ping: {ping_status}, dns: {dns_status}")
    logger.info("#" * 50)
else:
    logger.info("# Preparing for execution!")
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
    for subnet in enabled_subnets:
        logger.info(f"# Working on subnet: {subnet[1]}")
        try:
            ip_addresses = [ _ for _ in ip_network(subnet[1], strict=False)]
            print(ip_addresses)
        except Exception as e:
            logger.critical(f"# Skipping subnet {subnet[1]}, beacuse: {e}")
