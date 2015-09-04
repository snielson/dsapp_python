import sys
import time
import threading
import itertools
 
class progress_bar_loading(threading.Thread):

    def __init__(self):
        threading.Thread.__init__(self)
        self.event = threading.Event()
 
    def stop(self):
        self.event.set()
        print '\n',

    def run(self):
        spinner = itertools.cycle(['[-]', '[/]', '[|]', '[\\]'])
        while (not self.event.is_set()):
            sys.stdout.write(spinner.next())
            sys.stdout.flush()
            time.sleep(0.1)
            if not self.event.is_set():
                sys.stdout.write('\b\b\b')


if __name__ == '__main__':
    p = progress_bar_loading()
    print 'Loading...',
    p.start()
    time.sleep(10)
    p.stop()
    print 'Done'
