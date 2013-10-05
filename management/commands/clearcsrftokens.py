__author__ = 'renevanhoek'

from django.conf import settings
from django.core.management.base import NoArgsCommand
import session_csrf
import os
import stat
import datetime
import fnmatch

class Command(NoArgsCommand):
    help = "Can be run as a cronjob or directly to clean out expired csrf tokens."

    def handle_noargs(self, **options):
        self.WalkAndPrune()

    def ExamineFile(self, filename, ref_date):
        if not fnmatch.fnmatch(os.path.basename(filename), session_csrf.CSRF_COOKIE_NAME + '*'):
            return

        statinfo = os.stat(filename)
        create_date = datetime.datetime.fromtimestamp(statinfo[stat.ST_CTIME])

        diff_c = ref_date - create_date

        if diff_c.seconds > session_csrf.CSRF_TOKEN_TTL:
            os.remove(filename)

    def WalkAndPrune(self):
        ref_date = datetime.datetime.now()

        for root, dirs, files in os.walk(session_csrf.CsrfMiddleware._get_storage_path()):
            for f in files:
                self.ExamineFile(os.path.join(root, f), ref_date)

