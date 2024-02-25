import logging, os, sqlite3, sys, re
from subprocess import Popen, PIPE
from logging.handlers import RotatingFileHandler
from argparse import ArgumentParser, BooleanOptionalAction
from helper import validateSubnet, validateIpv4, Collector, ipv4
from ipaddress import ip_network
from shutil import which
from socket import gethostbyaddr
from platform import system
from queue import Queue
from jinja2 import Environment, FileSystemLoader

CWD = os.path.sep.join(os.path.abspath(__file__).split(os.path.sep)[:-1])
DB = os.path.sep.join([CWD,'database','pypam.db'])
LOGS = os.path.sep.join([CWD,'logs'])
NUM_THRDS = os.cpu_count()
TO_OVERRIDE = dict()
folders = ['database', 'logs','output']

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
group.add_argument('--list-overrides', action = BooleanOptionalAction, help = "Lists overrides if present!")
group.add_argument('--add-override', action = BooleanOptionalAction, help = "Adds new override or updates existing one!")
group.add_argument('--delete-override', type = str, help = "Deletes the given override!")
group.add_argument('--run', action= BooleanOptionalAction, help = "Executes the tool!")
group.add_argument('--generate-site', action = BooleanOptionalAction, help = "Generates static site from template!")
args = parser.parse_args()

databases = {
    "subnets" : {
            "create_table" : """
CREATE TABLE IF NOT EXISTS subnets (
id INTEGER PRIMARY KEY AUTOINCREMENT,
subnet TEXT,
description TEXT,
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
        },
    "overrides" : { 
            "create_table" : """
CREATE TABLE IF NOT EXISTS overrides (
id INTEGER PRIMARY KEY AUTOINCREMENT,
address TEXT,
dns TEXT);
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
    subnet_description = input("Please specify the description(N.A.): ")
    if not subnet_description:
        subnet_description = "N.A."
    logger.info(f"# Adding subnet {args.add_subnet} to the database with description: {subnet_description}, if not already there!")
    with sqlite3.connect(DB) as connection:
        exists = [ _ for _ in connection.execute(f"SELECT 1 FROM subnets WHERE subnet='{args.add_subnet}'")]
        if not exists: 
            logger.info("# No existsing record, adding...")
            result = connection.execute(f"INSERT INTO subnets (subnet, description, status) VALUES ('{args.add_subnet}','{subnet_description}',1)")
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
            logger.info("#" * 78)
            logger.info("#          Subnet           #        Description        #       Status       #")
            logger.info("#" * 78)
            for subnet in subnets:
                logger.info(f"# {subnet[1]:^25} # {subnet[2]:^25} # {('Enabled' if subnet[3] else 'Disabled'):^18} #")

        else:
            logger.critical("# Currently no subnets are recorded in the database!")
    logger.info("#" * 78)
    connection.close()
elif args.list_overrides:
    logger.info("# Preparing for execution.")
    with sqlite3.connect(DB) as connection:
        overrides = [ _ for _ in connection.execute("SELECT * FROM overrides")]
        if overrides:
            logger.info("#" * 56)
            logger.info("#          Address       #         DNS                 #")
            logger.info("#" * 56)
            for override in overrides:
                logger.info(f"# {override[1]:^22} # {override[2]:^27} #")
        else:
            logger.critical("# Currently there are no overrides defined in the table!")
    logger.info("#" * 56)
    connection.close()
elif args.delete_override:
    logger.info("# Preparing for execution.")
    logger.info("# Checking if override is valid...")
    if not ipv4.match(args.delete_override):
        logger.critical("# The specified override is invalid!")
        logger.info("#" * 50)
        sys.exit(-1)
    with sqlite3.connect(DB) as connection:
        logger.info("# Checking for existing record...")
        exists = [ _ for _ in connection.execute(f"SELECT 1 FROM overrides WHERE address='{args.delete_override}'")]
        if exists:
            logger.info("# Deleting record!")
            connection.execute(f"DELETE FROM overrides WHERE address='{args.delete_override}'")
        else:
            logger.info("# Override is not present, cannot delete!")
    logger.info("#" * 50)
    connection.close()
elif args.add_override:
    logger.info("# Preparing for execution")
    address = input("Please enter a valid Ipv4 address: ")
    if not ipv4.match(address):
        logger.critical("The Ipv4 address you entered is invalid!")
        logger.info("#" * 50)
        sys.exit(-1)
    dns = input("Please enter a valid DNS(FQDN): ")
    if not dns:
        logger.critical("# Cannot be empty!")
        logger.info("#" * 50)
        sys.exit(-1)
    logger.info(f"# Inserting or updating {address} with {dns}")
    with sqlite3.connect(DB) as connection:
        logger.info("# Checking for existing record...")
        exists = [ _ for _ in connection.execute(f"SELECT 1 FROM overrides WHERE address='{address}'")]
        if exists:
            logger.info("# Updating existing record.")
            connection.execute(f"UPDATE overrides SET dns='{dns}' WHERE address='{address}'")
        else:
            logger.info("# Inserting new record.")
            connection.execute(f"INSERT INTO overrides (address, dns) VALUES('{address}','{dns}')")
    logger.info("#" * 50)
    connection.close()
elif args.run:
    logger.info("# Preparing for execution!")
    logger.info("# Checking for overrides file...")
    with sqlite3.connect(DB) as connection:
        overrides = [ _ for _ in connection.execute("SELECT * FROM overrides")]

    if overrides:
        logger.info("# Found overrides")
        for override in overrides:
            TO_OVERRIDE[override[1]] = override[2]
    else:
        logger.info("# There are no overrides.")

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
    enabled_subnets = [ _ for _ in subnets if _[3] == 1]
    if not enabled_subnets:
        logger.critical("# There are no enabled subnets, exiting!")
        sys.exit(-1)
    logger.info("# This is the list of enabled subnets:")
    for subnet in enabled_subnets:
        logger.info(f"\t{subnet[1]} :: {subnet[2]}")
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
elif args.generate_site:
    logger.info("# Preparing for execution!")
    logger.info("# Looking for templates directory and index.html file.")
    if not os.path.isdir(os.path.sep.join([CWD,"templates"])):
        logger.critical("# Cannot find templates directory!")
        sys.exit(-1)
    if not os.path.isfile(os.path.sep.join([CWD,'templates','index.html'])):
        logger.critical("# Cannot find index.html file!")
        sys.exit(-1)
    logger.info("# Found both!")
    logger.info("# Initializing Jinja2")
    environment = Environment(loader=FileSystemLoader(os.path.sep.join([CWD,"templates"])))
    template = environment.get_template("index.html")
    subnet_template = environment.get_template("subnet.html")
    logger.info("# Pulling subnet information!")
    with sqlite3.connect(DB) as connection:
        subnets = [ _ for _ in connection.execute("SELECT * FROM subnets") ]
        overrides = [ _ for _ in connection.execute("SELECT * FROM overrides") ]

    if not subnets:
        logger.critical("# Cannot find any subnets")
        sys.exit(-1)

    if overrides:
        logger.info("# Generating with overrides.")
        content = template.render(name="Subnets",subnets=subnets, oname = "Overrides", overrides = overrides)
    else:
        logger.info("# Generating without overrides.")
        content = template.render(name="Subnets",subnets=subnets)

    with open(os.path.sep.join([CWD,'output','index.html']), mode="w", encoding="utf-8") as message:
        message.write(content)
    logging.info("# Pulling subnet related information from Enabled Subnets!")
    enabled_subnets = [ _ for _ in subnets if _[3] == 1 ]
    if not enabled_subnets:
        logger.critical("# There are no enabled subnets")
        sys.exit(-1)

    for subnet in enabled_subnets:
        logger.info(f"# Working on subnet: {subnet[1]}")
        try:
            subnet_addresses = [ _ for _ in ip_network(subnet[1], strict=False)][1:-1]
        except Exception as e:
            logger.critical(f"# Skipping subnet {subnet[1]}, beacuse: {e}")
            continue

        addresses_of_subnet = []
        with sqlite3.connect(DB) as connection:
            for address in subnet_addresses:
                exists = [ _ for _ in connection.execute(f"SELECT * FROM status WHERE address='{str(address)}'") ]
                if exists:
                    logger.info(exists)
                    addresses_of_subnet.append(exists[0])
                else:
                    logger.warning(f"# Database has no information about this address: {str(address)}")
        content = subnet_template.render(name = f"{str(subnet[1])}", addresses = addresses_of_subnet)
        with open(os.path.sep.join([CWD,'output',f"{subnet[1].split('/')[0].replace('.','')}.html"]), mode="w", encoding="utf-8") as message:
            message.write(content)
    logger.info("# Process complete, check outputs folder for static files.")
    logger.info("#" * 50)
