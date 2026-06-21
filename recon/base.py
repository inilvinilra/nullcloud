class ReconResult:
    def __init__(self, name):
        self.name = name
        self.data = {}
        self.errors = []


class BaseRecon:
    name = ""
    needs_key = False

    def run(self, domain, network_map, config):
        raise NotImplementedError
