"""Provider-owned processing terms and qualified destination membership."""

from .errors import LasaError

APPROVED_PROCESSING = "approved_processing"
DOMAIN_ONLY = "provider_domain_only"


def modes(rule):
    return rule.get("processing_modes", [APPROVED_PROCESSING])


def qualified_domain(config, policy):
    domain = policy.get("processing_domain")
    if (
        domain
        and domain["qualified_config"] == config.revision
        and domain["qualified_deployment"] == config.document["service"].get("deployment_revision")
    ):
        return domain
    return None


def permits(authority, destination):
    return authority["selected_offer"]["processing"]["mode"] != DOMAIN_ONLY or (
        destination in authority["processing_members"]
    )


def permits_child(authority, offer):
    terms = authority["selected_offer"]["processing"]
    return terms["mode"] != DOMAIN_ONLY or offer["processing"] == terms


def check(config, policy, rule, authority, destination=None):
    terms = authority["selected_offer"]["processing"]
    if terms["mode"] not in modes(rule):
        raise LasaError("processing_unavailable", 503)
    if terms["mode"] == DOMAIN_ONLY:
        domain = qualified_domain(config, policy)
        if (
            not domain
            or domain["id"] != terms["domain"]
            or authority["contract"] not in domain["qualified_contracts"]
            or destination is not None
            and (destination not in domain["members"] or not permits(authority, destination))
        ):
            raise LasaError("processing_unavailable", 503)
