import os
import gzip
import logging
import logging.handlers

class GZipRotator:
    def __call__(self, source, dest):
        os.rename(source, dest)
        f_in = open(dest, 'rb')
        f_out = gzip.open("%s.gz" % dest, 'wb')
        f_out.writelines(f_in)
        f_out.close()
        f_in.close()
        os.remove(dest)

class Logger():

    def __init__(self, folder, program):
        self.folder = folder
        self.program = program

    def getLogger(self):
        if not os.path.exists(self.folder):
            os.makedirs(self.folder)

        # Set up a specific logger with our desired output level
        logger = logging.getLogger(self.program)
        logger.setLevel(logging.INFO)

        # Add the log message handler to the logger
        handler = logging.handlers.TimedRotatingFileHandler(
              self.folder + "/" + self.program + ".log",
              when='D',
              backupCount=30)

        # create formatter
        formatter = logging.Formatter("%(asctime)s %(name)s: %(message)s")
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.rotator = GZipRotator()

        return logger
