# ElasticArmor | (c) 2016 NETWAYS GmbH | GPLv2+

from setuptools import setup

setup(
    name='elasticarmor',
    version='0.9',
    license='GPLv2+',
    author='NETWAYS GmbH',
    author_email='info@netways.de',
    url='https://www.netways.org/projects/elasticarmor',
    description='HTTP reverse proxy to secure Elasticsearch.',
    long_description='ElasticArmor is a HTTP reverse proxy placed in front of'
                     ' Elasticsearch to regulate access to its REST api.',
    packages=['lib/elasticarmor'],
    zip_safe=False
)
