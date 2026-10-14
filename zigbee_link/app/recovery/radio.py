from dataclasses import dataclass
from .model import Reference
from .mqtt import ReportingReply

# Only unambiguous standard ZCL attribute IDs. Unknown vendor attributes do not
# become proof by guessing that any returned configuration belongs to the request.
ATTRIBUTES = {("genOnOff", "onOff"): 0, ("genLevelCtrl", "currentLevel"): 0,
              ("genBasic", "zclVersion"): 0, ("genBasic", "manufacturerName"): 4,
              ("genBasic", "modelId"): 5,
              ("msTemperatureMeasurement", "measuredValue"): 0,
              ("msRelativeHumidity", "measuredValue"): 0,
              ("msIlluminanceMeasurement", "measuredValue"): 0}


@dataclass(frozen=True)
class RadioEvidence:
    confirmed: bool
    reason: str
    expires_at: float = 0


class RadioVerifier:
    def validate(self, reference: Reference, reply: ReportingReply, generation: str, now: float) -> RadioEvidence:
        if reply.reference != reference or reply.retained or reply.generation != generation or not 0 <= now - reply.at <= 900:
            return RadioEvidence(False, "radio_stale_or_foreign")
        data = reply.data
        attribute = ATTRIBUTES.get((reference.cluster, reference.attribute))
        if attribute is None:
            return RadioEvidence(False, "radio_attribute_unsupported")
        if reply.status != "ok" or not isinstance(data, dict) or data.get("id") != reference.ieee or data.get("endpoint") != reference.endpoint or data.get("cluster") != reference.cluster:
            return RadioEvidence(False, "radio_read_unconfirmed")
        configs = data.get("configs")
        if not isinstance(configs, list) or len(configs) != 1:
            return RadioEvidence(False, "radio_invalid_configuration")
        config = configs[0]
        if not isinstance(config, dict) or type(config.get("status")) is not int or config["status"] != 0 or type(config.get("attrId")) is not int or config["attrId"] != attribute or config.get("direction") != 0:
            return RadioEvidence(False, "radio_read_unconfirmed")
        return RadioEvidence(True, "radio_exchange_confirmed", reply.at + 900)
