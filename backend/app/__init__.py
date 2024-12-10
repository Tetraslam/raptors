import logging
import sys

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)

# Set logging levels for specific loggers
logging.getLogger('app.services.scanner').setLevel(logging.DEBUG)
logging.getLogger('app.services.vulnerability_scanner').setLevel(logging.DEBUG)
logging.getLogger('app.main').setLevel(logging.DEBUG)
