from setuptools import setup

setup(
    name='elasticarmor',
    version='0.0',
    author='NETWAYS GmbH',
    author_email='info@netways.de',
    description='a transparent proxy for securing Elasticsearch',
    license='GPLv2+',
    url='https://www.netways.org/projects/elasticarmor',
    long_description='The ElasticArmor is a transparent HTTP proxy for securing '
                     'Elasticsearch by permitting specific users to access only '
                     'specific data.',
    packages=['libelasticarmor'],
    zip_safe=False
)
