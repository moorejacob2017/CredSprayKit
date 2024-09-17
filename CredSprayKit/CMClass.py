import time


class CooldownManager:
    def __init__(self, items, max_counters=0, time_limit=0):
        self.items = list(set(items))
        self.cooldowns = [False for _ in items]
        self.counters = [0 for _ in items]
        self.times = [None for _ in items]
        self.exclude = [False for _ in items]
        self.checkout = [False for _ in items]
        
        self.max_counters = max_counters
        self.time_limit = time_limit

    def all_unavailable(self):
        # Check if all are unavailable
        self.update_cooldowns()
        all_un = True
        for i in range(len(self.items)):
            if not self.cooldowns[i] and not self.checkout[i]:
                if not self.exclude[i]:
                    all_un = False
                    break
        return all_un

    def check_out(self):
        if all(self.exclude):
            return None

        # Block Execution and wait for availability
        #while self.all_unavailable():
        #    pass

        for i, on_cooldown in enumerate(self.cooldowns):
            if not on_cooldown and not self.checkout[i] and not self.exclude[i]:
                self.checkout[i] = True
                return self.items[i]

    def check_in(self, item):
        index = self.items.index(item)
        self.checkout[index] = False
        if not self.max_counters <= 0:
            now = time.time()
            self.counters[index] += 1
            self.times[index] = now
            if self.counters[index] >= self.max_counters:
                self.cooldowns[index] = True

    def check_in_no_count(self, item):
        index = self.items.index(item)
        self.checkout[index] = False
            
    def exclude_item(self, item):
        index = self.items.index(item)
        self.exclude[index] = True

    def reset_excluded(self):
        for i in range(len(self.items)):
            self.exclude[i] = False

    def reset_checkout(self):
        for i in range(len(self.items)):
            self.checkout[i] = False

    def update_cooldowns(self):
        for i in range(len(self.items)):
            now = time.time()
            if self.times[i] and now - self.times[i] > self.time_limit:
                self.times[i] = None
                self.counters[i] = 0
                self.cooldowns[i] = False

    def debug_print_cooldowns(self):
        time.sleep(0.015)
        print('----------------------------------')
        for i, item in enumerate(self.items):
            now = time.time()
            if self.times[i]:
                curr_cooldown = now - self.times[i]
                print(f"{item: <15}: {self.counters[i]: <3} {self.time_limit - curr_cooldown: <20}")
            else:
                print(f"{item: <15}: {0: <3} {0: <20}")