import json

JSON_FLAG = "__attack_candidate__"


class AttackCandidateEncoder(json.JSONEncoder):

    def default(self, obj):
        if isinstance(obj, AttackCandidate):
            return {
                JSON_FLAG: True,
                "vulnerability_type": obj.vul_type,
                "attack_details": obj.attack_details,
                "results": obj.results
            }
        return json.JSONEncoder.default(self, obj)


def as_attack_candidate(dct):
    if JSON_FLAG in dct:
        return AttackCandidate(dct["vulnerability_type"], dct["attack_details"], dct["results"])
    return dct


class AttackCandidate:

    def __init__(self, vul_type, attack_details, results):
        self.vul_type = vul_type
        self.attack_details = attack_details
        self.results = results

    @staticmethod
    def dump_candidates(candidates, f):
        json.dump(candidates, f, cls=AttackCandidateEncoder)

    @staticmethod
    def load_candidates(f):
        return json.load(f, object_hook=as_attack_candidate)
