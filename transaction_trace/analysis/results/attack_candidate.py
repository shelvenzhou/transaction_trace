import json

JSON_FLAG = "__attack_candidate__"


class AttackCandidateEncoder(json.JSONEncoder):

    def default(self, obj):
        if isinstance(obj, AttackCandidate):
            return {
                JSON_FLAG: True,
                "type": obj.type,
                "details": obj.attack_details,
                "intentions": obj.intentions,
                "results": obj.results,
            }
        return json.JSONEncoder.default(self, obj)


def as_attack_candidate(dct):
    if JSON_FLAG in dct:
        return AttackCandidate(dct["type"], dct["details"], dct["intentions"], dct["results"])
    return dct


class AttackCandidate:

    def __init__(self, vul_type, details, intentions, results):
        self.type = vul_type
        self.details = details
        self.intentions = intentions
        self.results = results


class AttackCandidateExporter:

    @staticmethod
    def dump_candidates(candidates, f):
        json.dump(candidates, f, indent="\t", cls=AttackCandidateEncoder)
        f.flush()

    @staticmethod
    def load_candidates(f):
        return json.load(f, object_hook=as_attack_candidate)

    def __init__(self, f):
        self.file = f
        self.first_item = True

        self.file.write(b"[")

    def __del__(self):
        self.file.write(b"]")

    def dump_candidate(self, candidate):
        if self.first_item:
            json.dump(candidate, self.file, indent="\t", cls=AttackCandidateEncoder)
            self.first_item = False
        else:
            self.file.write(b",")
            json.dump(candidate, self.file, indent="\t", cls=AttackCandidateEncoder)
        self.file.flush()
