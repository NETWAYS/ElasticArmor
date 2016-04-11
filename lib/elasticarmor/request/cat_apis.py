# ElasticArmor | (c) 2016 NETWAYS GmbH | GPLv2+

from elasticarmor.request import *


class CatApiRequest(ElasticRequest):
    # Consider this as a placeholder. The cat API is way more comprehensive than is_valid may convey.
    # This request handler should be superseded by more sophisticated solutions in the future.

    def is_valid(self):
        return self.path.startswith('/cat')

    @Permission('api/cat', scope='cluster')
    def inspect(self, client):
        pass
