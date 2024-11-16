import yaml
import logging

def load_config(config_path='config/config.yaml'):
    with open(config_path, 'r') as file:
        config = yaml.safe_load(file)
    return config

def setup_logging():
    logging.basicConfig(
        filename='agent.log',
        filemode='a',
        format='%(asctime)s - %(levelname)s - %(message)s',
        level=logging.INFO
    )
    logging.info("Logging initialized.")

if __name__ == "__main__":
    setup_logging()
    config = load_config()
    logging.info("Configuration loaded successfully.")
    print("Initialization complete.")
