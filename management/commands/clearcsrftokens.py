__author__ = 'renevanhoek'

from django.conf import settings
from django.core.management.base import NoArgsCommand
from django.utils.encoding import force_text

import re
import session_csrf
import os
import stat
import datetime
import fnmatch

class Command(NoArgsCommand):
    help = "Can be run as a cronjob or directly to clean out expired csrf tokens."

    def handle_noargs(self, **options):
        self.WalkAndPrune()

    def ExamineFile(self, filename, ref_date, cookie_name, csrf_token_ttl):
        if not fnmatch.fnmatch(os.path.basename(filename), cookie_name + '*'):
            return

        statinfo = os.stat(filename)
        create_date = datetime.datetime.fromtimestamp(statinfo[stat.ST_CTIME])

        diff_c = ref_date - create_date

        if diff_c.seconds > csrf_token_ttl:
            os.remove(filename)

    def WalkAndPrune(self):
        ref_date = datetime.datetime.now()
        cookie_name = getattr(settings, 'CSRF_COOKIE_NAME', 'csrftoken')
        csrf_token_ttl = float(getattr(settings, 'CSRF_TOKEN_TTL', 7200 ) )

        result = re.match('[a-zA-Z0-9_-]+$', force_text(cookie_name))
        if result is None:
            raise EnvironmentError("Only letters, numbers, '-' and '_' are allowed in the csrf cookie-name")

        for root, dirs, files in os.walk(session_csrf.CsrfMiddleware._get_storage_path()):
            for f in files:
                self.ExamineFile(os.path.join(root, f), ref_date, cookie_name, csrf_token_ttl)

