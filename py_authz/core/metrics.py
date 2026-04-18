class Metrics:
    def __init__(self):
        self.counters = {}

    def incr(self, name: str):
        self.counters[name] = self.counters.get(name, 0) + 1


metrics = Metrics()
