"""Constants for the Mikrotik firewall manager integration."""

DOMAIN = "mikrotik_firewall"

CONF_USER = "username"
CONF_PASS = "password"
CONF_HOST = "host"
CONF_FILTER = "filter"
CONF_CHAIN = "chain"
CONF_SSL = "use_ssl"

CONF_RULES = "rules"
CONF_RULE_ID = "rule_id"
CONF_RULE_NAME = "rule_name"

# entity name prefix
ENTITY_NAME_PREFIX = "firewall_rule"

# mikrotik api resources
MK_API_IP_FIREWALL_FILTER = "/ip/firewall/filter"

DISABLED_TRUE = "true"
DISABLED_FALSE = "false"
