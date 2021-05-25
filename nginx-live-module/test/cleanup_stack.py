### Cleanup stack - enables automatic cleanup after a test is run
class CleanupStack:
    def __init__(self):
        self.items = []

    def push(self, callback):
        self.items.append(callback)

    def reset(self):
        for i in xrange(len(self.items), 0 , -1):
            self.items[i - 1]()
        self.items = []

cleanupStack = CleanupStack()
